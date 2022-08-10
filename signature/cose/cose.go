package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/veraison/go-cose"
)

const MediaTypeEnvelope = "application/cose"

func init() {
	if err := signature.RegisterEnvelopeType(MediaTypeEnvelope, NewEnvelope, ParseEnvelope); err != nil {
		panic(err)
	}
}

// Protected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerKeyExpiry                       = "io.cncf.notary.expiry"
	headerKeySigningTime                  = "io.cncf.notary.signingTime"
	headerKeyAuthenticSigningTime         = "io.cncf.notary.authenticSigningTime"
	headerKeySigningScheme                = "io.cncf.notary.signingScheme"
	headerKeyVerificationPlugin           = "io.cncf.notary.verificationPlugin"
	headerKeyVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
	headerKeyCrit                         = "crit"
	headerKeyAlg                          = "alg"
	headerKeyCty                          = "cty"
)

// Unprotected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerKeyTimeStampSignature = "io.cncf.notary.timestampSignature"
	headerKeySigningAgent       = "io.cncf.notary.signingAgent"
)

// Map of signature.Algorithm to cose.Algorithm
var signatureAlgCOSEAlgMap = map[signature.Algorithm]cose.Algorithm{
	signature.AlgorithmPS256: cose.AlgorithmPS256,
	signature.AlgorithmPS384: cose.AlgorithmES384,
	signature.AlgorithmPS512: cose.AlgorithmPS512,
	signature.AlgorithmES256: cose.AlgorithmES256,
	signature.AlgorithmES384: cose.AlgorithmES384,
	signature.AlgorithmES512: cose.AlgorithmES512,
}

var coseAlgSignatureAlgMap = reverseMapCOSE(signatureAlgCOSEAlgMap)

func reverseMapCOSE(m map[signature.Algorithm]cose.Algorithm) map[cose.Algorithm]signature.Algorithm {
	n := make(map[cose.Algorithm]signature.Algorithm, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}

type envelope struct {
	coseEnvelope *cose.Sign1Message
}

type pluginSigner struct {
	signer signature.Signer
}

// Algorithm implements cose.Signer interface
func (coseSigner pluginSigner) Algorithm() cose.Algorithm {
	keySpec, err := coseSigner.signer.KeySpec()
	if err != nil {
		return 0
	}
	alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return 0
	}
	return alg
}

// Sign implements cose.Signer interface
func (coseSigner pluginSigner) Sign(rand io.Reader, digest []byte) ([]byte, error) {
	sig, err := coseSigner.signer.Sign(digest)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Sign implements signature.Envelope interface
// On success, this function returns the Cose signature envelope byte slice
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	errorFunc := func(s string) error {
		if s != "" {
			return errors.New(s)
		}
		return errors.New("SignRequest is malformed")
	}
	keySpec, err := req.Signer.KeySpec()
	if err != nil {
		return nil, errorFunc(err.Error())
	}
	alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return nil, errorFunc(err.Error())
	}

	msgToSign := cose.NewSign1Message()
	// payload
	msgToSign.Payload = req.Payload.Content
	// protected headers
	msgToSign.Headers.Protected.SetAlgorithm(alg)
	err = generateCoseProtectedHeaders(req, msgToSign.Headers.Protected)
	if err != nil {
		return nil, err
	}
	// unprotected headers
	msgToSign.Headers.Unprotected[headerKeySigningAgent] = req.SigningAgent
	// TODO: needs to add headerKeyTimeStampSignature here, which requires
	// updates of SignRequest

	signer := req.Signer
	sig, certs, err := sign(req, signer, msgToSign, alg)
	if err != nil {
		return nil, err
	}
	if err := validateCertificateChain(certs, req.SigningTime, alg, errorFunc); err != nil {
		return nil, err
	}
	err = e.coseEnvelope.UnmarshalCBOR(sig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify implements signature.Envelope interface
// Note: Verfiy only verifies integrity
func (e *envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	if e.coseEnvelope == nil {
		return nil, nil, &signature.MalformedSignatureError{Msg: "missing Cose signature envelope"}
	}
	certs, ok := e.coseEnvelope.Headers.Unprotected[cose.HeaderLabelX5Chain].([][]byte)
	if !ok || len(certs) == 0 {
		return nil, nil, &signature.MalformedSignatureError{Msg: "malformed certificate chain"}
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, nil, err
	}

	// verify COSE
	publicKeyAlg, err := getSignatureAlgorithm(cert)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := cose.NewVerifier(publicKeyAlg, cert.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	err = e.coseEnvelope.Verify(nil, verifier)
	if err != nil {
		return nil, nil, err
	}

	payload, err := e.Payload()
	if err != nil {
		return nil, nil, err
	}
	signerInfo, err := e.SignerInfo()
	if err != nil {
		return nil, nil, err
	}
	return payload, signerInfo, nil
}

// Payload implements signature.Envelope interface
func (e *envelope) Payload() (*signature.Payload, error) {
	payload := signature.Payload{}
	if e.coseEnvelope == nil {
		return nil, &signature.MalformedSignatureError{Msg: "missing Cose signature envelope"}
	}
	if len(e.coseEnvelope.Payload) == 0 {
		return nil, &signature.MalformedSignatureError{Msg: "missing payload"}
	}
	payload.Content = e.coseEnvelope.Payload
	if cty, ok := e.coseEnvelope.Headers.Protected[cose.HeaderLabelContentType]; !ok {
		return nil, &signature.MalformedSignatureError{Msg: "missing Content type"}
	} else {
		if payload.ContentType, ok = cty.(string); !ok {
			return nil, &signature.MalformedSignatureError{Msg: "content type requires tstr type"}
		}
	}
	if payload.ContentType != signature.MediaTypePayloadV1 {
		return nil, &signature.MalformedSignatureError{Msg: "content type requires application/vnd.cncf.notary.payload.v1+json, but got " + payload.ContentType}
	}

	return &payload, nil
}

// SignerInfo implements signature.Envelope interface
func (e *envelope) SignerInfo() (*signature.SignerInfo, error) {
	signInfo := signature.SignerInfo{}
	if e.coseEnvelope == nil {
		return nil, &signature.MalformedSignatureError{Msg: "missing Cose signature envelope"}
	}

	// parse protected headers
	err := parseProtectedHeaders(&e.coseEnvelope.Headers, &signInfo)
	if err != nil {
		return nil, err
	}

	// parse signature
	sig := e.coseEnvelope.Signature
	if len(sig) == 0 {
		return nil, &signature.MalformedSignatureError{Msg: "cose envelope missing signature"}
	}
	signInfo.Signature = sig

	// parse unprotected headers
	// x5chain
	var certChain []*x509.Certificate
	certs, ok := e.coseEnvelope.Headers.Unprotected[cose.HeaderLabelX5Chain].([][]byte)
	if !ok || len(certs) == 0 {
		return nil, &signature.MalformedSignatureError{Msg: "missing certificate chain"}
	}
	for _, certBytes := range certs {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certChain = append(certChain, cert)
	}
	signInfo.CertificateChain = certChain
	// signingAgent
	signInfo.UnsignedAttributes.SigningAgent = e.coseEnvelope.Headers.Unprotected[headerKeySigningAgent].(string)
	// timestampSignature
	signInfo.TimestampSignature = e.coseEnvelope.Headers.Unprotected[headerKeyTimeStampSignature].([]byte)

	return &signInfo, nil
}

// NewEnvelope initializes an empty Cose signature envelope
func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{coseEnvelope: &cose.Sign1Message{}},
	}
}

// ParseEnvelope parses envelopeBytes to a Cose signature envelope
func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	var coseEnvelope cose.Sign1Message
	err := coseEnvelope.UnmarshalCBOR(envelopeBytes)
	if err != nil {
		return nil, err
	}
	return &base.Envelope{
		Envelope: &envelope{coseEnvelope: &coseEnvelope},
		Raw:      envelopeBytes,
	}, nil
}

func validateCertificateChain(certChain []*x509.Certificate, signTime time.Time, expectedAlg cose.Algorithm, f func(string) error) error {
	if len(certChain) == 0 {
		return f("certificate-chain not present or is empty")
	}

	err := nx509.ValidateCodeSigningCertChain(certChain, signTime)
	if err != nil {
		return f(fmt.Sprintf("certificate-chain is invalid, %s", err))
	}

	resSignAlgo, err := getSignatureAlgorithm(certChain[0])
	if err != nil {
		return f(err.Error())
	}
	if resSignAlgo != expectedAlg {
		return f("mismatch between signature algorithm derived from signing certificate and signing algorithm specified")
	}

	return nil
}

// getSignatureAlgorithm picks up a recommended signing algorithm for given certificate.
func getSignatureAlgorithm(signingCert *x509.Certificate) (cose.Algorithm, error) {
	keySpec, err := signature.ExtractKeySpec(signingCert)
	if err != nil {
		return 0, err
	}
	return getSignatureAlgorithmFromKeySpec(keySpec)
}

func getSignatureAlgorithmFromKeySpec(keySpec signature.KeySpec) (cose.Algorithm, error) {
	switch keySpec.Type {
	case signature.KeyTypeRSA:
		switch keySpec.Size {
		case 2048:
			return signatureAlgCOSEAlgMap[signature.AlgorithmPS256], nil
		case 3072:
			return signatureAlgCOSEAlgMap[signature.AlgorithmPS384], nil
		case 4096:
			return signatureAlgCOSEAlgMap[signature.AlgorithmPS512], nil
		default:
			return 0, errors.New("key size not supported")
		}
	case signature.KeyTypeEC:
		switch keySpec.Size {
		case 256:
			return signatureAlgCOSEAlgMap[signature.AlgorithmES256], nil
		case 384:
			return signatureAlgCOSEAlgMap[signature.AlgorithmES384], nil
		case 512:
			return signatureAlgCOSEAlgMap[signature.AlgorithmES512], nil
		default:
			return 0, errors.New("key size not supported")
		}
	default:
		return 0, errors.New("key type not supported")
	}
}

func generateCoseProtectedHeaders(req *signature.SignRequest, protected cose.ProtectedHeader) error {
	// crit, signingScheme, expiry, signingTime, authenticSigningTime
	var crit []interface{}
	crit = append(crit, headerKeySigningScheme)
	protected[headerKeySigningScheme] = string(req.SigningScheme)
	if !req.Expiry.IsZero() {
		crit = append(crit, headerKeyExpiry)
		protected[headerKeyExpiry] = uint(req.Expiry.Unix())
	}
	switch req.SigningScheme {
	case signature.SigningSchemeX509:
		protected[headerKeySigningTime] = uint(req.SigningTime.Unix())
	case signature.SigningSchemeX509SigningAuthority:
		crit = append(crit, headerKeyAuthenticSigningTime)
		protected[headerKeyAuthenticSigningTime] = uint(req.SigningTime.Unix())
	default:
		return errors.New("SigningScheme: require notary.x509 or notary.x509.signingAuthority")
	}
	protected[cose.HeaderLabelCritical] = crit

	// content type
	protected[cose.HeaderLabelContentType] = req.Payload.ContentType

	// extended attributes
	for _, elm := range req.ExtendedSignedAttributes {
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
		protected[elm.Key] = elm.Value
	}

	return nil
}

func sign(req *signature.SignRequest, signer signature.Signer, msgToSign *cose.Sign1Message, alg cose.Algorithm) ([]byte, []*x509.Certificate, error) {
	var coseSigner cose.Signer
	var err error
	if localSigner, ok := signer.(signature.LocalSigner); ok {
		switch key := localSigner.PrivateKey().(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			// Use go-cose's signer
			coseSigner, err = cose.NewSigner(alg, key.(crypto.Signer))
			if err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, errors.New("unsupported key type")
		}
	} else {
		// Use External plugin's signer
		coseSigner = pluginSigner{signer: signer}
	}
	err = msgToSign.Sign(rand.Reader, nil, coseSigner)
	if err != nil {
		return nil, nil, err
	}
	certs, err := signer.CertificateChain()
	if err != nil {
		return nil, nil, err
	}
	certChain := make([][]byte, len(certs))
	for i, c := range certs {
		certChain[i] = c.Raw
	}
	msgToSign.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChain
	sig, err := msgToSign.MarshalCBOR()
	if err != nil {
		return nil, nil, err
	}

	return sig, certs, nil

}

func parseProtectedHeaders(headers *cose.Headers, signInfo *signature.SignerInfo) error {
	if len(headers.RawProtected) == 0 {
		return &signature.MalformedSignatureError{Msg: "missing cose envelope protected header"}
	}
	protected := headers.Protected

	// crit
	err := validateCritHeaders(protected)
	if err != nil {
		return err
	}

	// alg
	alg, err := protected.Algorithm()
	if err != nil {
		return err
	}
	sigAlg, ok := coseAlgSignatureAlgMap[alg]
	if !ok {
		return &signature.MalformedSignatureError{Msg: "signature algorithm not supported: " + strconv.Itoa(int(alg))}
	}
	signInfo.SignatureAlgorithm = sigAlg

	// content type
	cty, ok := protected[cose.HeaderLabelContentType].(string)
	if !ok {
		return &signature.MalformedSignatureError{Msg: "malformed content type"}
	}
	if cty != signature.MediaTypePayloadV1 {
		return &signature.MalformedSignatureError{Msg: "content type requires application/vnd.cncf.notary.payload.v1+json, but got " + cty}
	}

	// signingTime, signingScheme
	signScheme, ok := protected[headerKeySigningScheme].(string)
	if !ok {
		return &signature.MalformedSignatureError{Msg: "malformed signScheme"}
	}
	switch signature.SigningScheme(signScheme) {
	case signature.SigningSchemeX509:
		signTime, ok := protected[headerKeySigningTime].(uint)
		if !ok {
			return &signature.MalformedSignatureError{Msg: "malformed signingTime under notary.x509"}
		}
		signInfo.SignedAttributes.SigningTime = time.Unix(int64(signTime), 0)
	case signature.SigningSchemeX509SigningAuthority:
		signTime, ok := protected[headerKeyAuthenticSigningTime].(uint)
		if !ok {
			return &signature.MalformedSignatureError{Msg: "malformed authenticSigningTime under notary.x509.signingAuthority"}
		}
		signInfo.SignedAttributes.SigningTime = time.Unix(int64(signTime), 0)
	default:
		return &signature.MalformedSignatureError{Msg: "unsupported signingScheme: " + signScheme}
	}
	signInfo.SigningScheme = signature.SigningScheme(signScheme)

	// expiry
	if exp, ok := protected[headerKeyExpiry].(uint); ok {
		signInfo.SignedAttributes.Expiry = time.Unix(int64(exp), 0)
	}

	// extended attributes
	extendedAttributes := headers.Protected
	delete(extendedAttributes, cose.HeaderLabelAlgorithm)
	delete(extendedAttributes, cose.HeaderLabelContentType)
	delete(extendedAttributes, cose.HeaderLabelCritical)
	delete(extendedAttributes, headerKeySigningTime)
	delete(extendedAttributes, headerKeyExpiry)
	delete(extendedAttributes, headerKeyAuthenticSigningTime)
	delete(extendedAttributes, headerKeySigningScheme)
	signInfo.SignedAttributes.ExtendedAttributes, err = getExtendedAttributes(protected, extendedAttributes)
	if err != nil {
		return err
	}

	return nil
}

// validateCritHeaders does a two-way check, namely:
// 1. validate that all critical headers are present in the protected bucket
// 2. validate that all required headers(as per spec) are marked critical
func validateCritHeaders(protected cose.ProtectedHeader) error {
	// This ensures all critical headers are present in the protected bucket.
	labels, err := protected.Critical()
	if err != nil {
		return err
	}
	// set of headers that must be marked as crit
	mustMarkedCrit := make(map[interface{}]struct{})
	mustMarkedCrit[headerKeySigningScheme] = struct{}{}
	signScheme, ok := protected[headerKeySigningScheme].(string)
	if !ok {
		return &signature.MalformedSignatureError{Msg: "signature missing io.cncf.notary.signingScheme"}
	}
	if signature.SigningScheme(signScheme) == signature.SigningSchemeX509SigningAuthority {
		mustMarkedCrit[headerKeyAuthenticSigningTime] = struct{}{}
	}
	if _, ok := protected[headerKeyExpiry].(uint); ok {
		mustMarkedCrit[headerKeyExpiry] = struct{}{}
	}

	for _, label := range labels {
		delete(mustMarkedCrit, label)
	}

	// validate that all required headers(as per spec) are marked as critical
	if len(mustMarkedCrit) != 0 {
		headers := make([]interface{}, 0, len(mustMarkedCrit))
		for k := range mustMarkedCrit {
			headers = append(headers, k)
		}
		return &signature.MalformedSignatureError{Msg: fmt.Sprintf("these required headers are not marked as critical: %v", headers)}
	}
	return nil
}

func getExtendedAttributes(protected, extendAttributes cose.ProtectedHeader) ([]signature.Attribute, error) {
	labels, err := protected.Critical()
	if err != nil {
		return nil, err
	}
	var extendedAttr []signature.Attribute
	for k, v := range extendAttributes {
		key, ok := k.(string)
		if !ok {
			return nil, errors.New("extendAttributes key requires string type")
		}
		extendedAttr = append(extendedAttr, signature.Attribute{
			Key:      key,
			Critical: contains(labels, key),
			Value:    v,
		})
	}
	return extendedAttr, nil
}

func contains(s []interface{}, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
