package cose

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
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
	headerLabelExpiry               = "io.cncf.notary.expiry"
	headerLabelSigningTime          = "io.cncf.notary.signingTime"
	headerLabelAuthenticSigningTime = "io.cncf.notary.authenticSigningTime"
	headerLabelSigningScheme        = "io.cncf.notary.signingScheme"
)

// Unprotected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerLabelTimeStampSignature = "io.cncf.notary.timestampSignature"
	headerLabelSigningAgent       = "io.cncf.notary.signingAgent"
)

// Map of signature.Algorithm to cose.Algorithm
var coseAlgSignatureAlgMap = map[cose.Algorithm]signature.Algorithm{
	cose.AlgorithmPS256: signature.AlgorithmPS256,
	cose.AlgorithmPS384: signature.AlgorithmPS384,
	cose.AlgorithmPS512: signature.AlgorithmPS512,
	cose.AlgorithmES256: signature.AlgorithmES256,
	cose.AlgorithmES384: signature.AlgorithmES384,
	cose.AlgorithmES512: signature.AlgorithmES512,
}

type remoteSigner struct {
	base signature.Signer
	alg  cose.Algorithm
}

func newRemoteSigner(base signature.Signer) (*remoteSigner, error) {
	keySpec, err := base.KeySpec()
	if err != nil {
		return nil, err
	}
	alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return nil, err
	}
	return &remoteSigner{
		base: base,
		alg:  alg,
	}, nil
}

// Algorithm implements cose.Signer interface
func (signer remoteSigner) Algorithm() cose.Algorithm {
	return signer.alg
}

// Sign implements cose.Signer interface
func (signer remoteSigner) Sign(rand io.Reader, digest []byte) ([]byte, error) {
	return signer.base.Sign(digest)
}

type envelope struct {
	base *cose.Sign1Message
}

// NewEnvelope initializes an empty Cose signature envelope
func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{},
	}
}

// ParseEnvelope parses envelopeBytes to a Cose signature envelope
func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(envelopeBytes); err != nil {
		return nil, err
	}
	return &base.Envelope{
		Envelope: &envelope{
			base: &msg,
		},
		Raw: envelopeBytes,
	}, nil
}

// Sign implements signature.Envelope interface
// On success, this function returns the Cose signature envelope byte slice
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	msg := cose.NewSign1Message()
	// payload
	msg.Payload = req.Payload.Content

	// unprotected headers
	msg.Headers.Unprotected[headerLabelSigningAgent] = req.SigningAgent
	// TODO: needs to add headerKeyTimeStampSignature here, which requires
	// updates of SignRequest

	var (
		signer cose.Signer
		err    error
	)
	reqSigner := req.Signer
	if localSigner, ok := reqSigner.(signature.LocalSigner); ok {
		key := localSigner.PrivateKey()
		if cryptoSigner, ok := key.(crypto.Signer); ok {
			keySpec, err := localSigner.KeySpec()
			if err != nil {
				return nil, err
			}
			alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
			if err != nil {
				return nil, err
			}
			signer, err = cose.NewSigner(alg, cryptoSigner)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("unsupported signing key")
		}
	} else {
		signer, err = newRemoteSigner(reqSigner)
		if err != nil {
			return nil, err
		}
	}
	// protected headers
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())
	if err := generateProtectedHeaders(req, msg.Headers.Protected); err != nil {
		return nil, err
	}

	// core sign process
	err = msg.Sign(rand.Reader, nil, signer)
	if err != nil {
		return nil, err
	}
	certs, err := reqSigner.CertificateChain()
	if err != nil {
		return nil, err
	}
	certChain := make([][]byte, len(certs))
	for i, c := range certs {
		certChain[i] = c.Raw
	}
	msg.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChain

	sig, err := msg.MarshalCBOR()
	if err != nil {
		return nil, err
	}
	e.base = msg
	return sig, nil
}

// Verify implements signature.Envelope interface
// Note: Verfiy only verifies integrity
func (e *envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	// sanity check
	if e.base == nil {
		return nil, nil, &signature.MalformedSignatureError{Msg: "missing Cose signature envelope"}
	}

	certs, ok := e.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([][]byte)
	if !ok || len(certs) == 0 {
		return nil, nil, errors.New("cose envelope malformed certificate chain")
	}
	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, nil, err
	}

	// core verify process
	publicKeyAlg, err := getSignatureAlgorithm(cert)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := cose.NewVerifier(publicKeyAlg, cert.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	err = e.base.Verify(nil, verifier)
	if err != nil {
		return nil, nil, err
	}

	// extract payload and signer info
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
	cty, ok := e.base.Headers.Protected[cose.HeaderLabelContentType]
	if !ok {
		return nil, &signature.MalformedSignatureError{Msg: "missing content type"}
	}
	var contentType string
	if contentType, ok = cty.(string); !ok {
		return nil, &signature.MalformedSignatureError{Msg: "content type requires tstr type"}
	}
	return &signature.Payload{
		ContentType: contentType,
		Content:     e.base.Payload,
	}, nil
}

// SignerInfo implements signature.Envelope interface
func (e *envelope) SignerInfo() (*signature.SignerInfo, error) {
	signInfo := signature.SignerInfo{}

	// parse protected headers
	err := parseProtectedHeaders(&e.base.Headers, &signInfo)
	if err != nil {
		return nil, err
	}

	// parse signature
	sig := e.base.Signature
	if len(sig) == 0 {
		return nil, &signature.MalformedSignatureError{Msg: "cose envelope missing signature"}
	}
	signInfo.Signature = sig

	// parse unprotected headers
	// x5chain
	certs, ok := e.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([][]byte)
	if !ok || len(certs) == 0 {
		return nil, errors.New("cose envelope malformed certificate chain")
	}
	var certChain []*x509.Certificate
	for _, certBytes := range certs {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certChain = append(certChain, cert)
	}
	signInfo.CertificateChain = certChain

	// signingAgent
	if h, ok := e.base.Headers.Unprotected[headerLabelSigningAgent].(string); ok {
		signInfo.UnsignedAttributes.SigningAgent = h
	}
	return &signInfo, nil
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
			return cose.AlgorithmPS256, nil
		case 3072:
			return cose.AlgorithmPS384, nil
		case 4096:
			return cose.AlgorithmPS512, nil
		default:
			return 0, errors.New("RSA: key size not supported")
		}
	case signature.KeyTypeEC:
		switch keySpec.Size {
		case 256:
			return cose.AlgorithmES256, nil
		case 384:
			return cose.AlgorithmES384, nil
		case 521:
			return cose.AlgorithmES512, nil
		default:
			return 0, errors.New("EC: key size not supported")
		}
	default:
		return 0, errors.New("key type not supported")
	}
}

func generateProtectedHeaders(req *signature.SignRequest, protected cose.ProtectedHeader) error {
	// crit, signingScheme, expiry, signingTime, authenticSigningTime
	crit := []interface{}{headerLabelSigningScheme}
	protected[headerLabelSigningScheme] = string(req.SigningScheme)
	switch req.SigningScheme {
	case signature.SigningSchemeX509:
		protected[headerLabelSigningTime] = req.SigningTime.Unix()
	case signature.SigningSchemeX509SigningAuthority:
		crit = append(crit, headerLabelAuthenticSigningTime)
		protected[headerLabelAuthenticSigningTime] = req.SigningTime.Unix()
	default:
		return errors.New("SigningScheme: require notary.x509 or notary.x509.signingAuthority")
	}

	if !req.Expiry.IsZero() {
		crit = append(crit, headerLabelExpiry)
		protected[headerLabelExpiry] = req.Expiry.Unix()
	}

	// content type
	protected[cose.HeaderLabelContentType] = req.Payload.ContentType

	// extended attributes
	for _, elm := range req.ExtendedSignedAttributes {
		if _, ok := protected[elm.Key]; ok {
			return fmt.Errorf("%v already exists in the protected header", elm.Key)
		}
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
		protected[elm.Key] = elm.Value
	}
	protected[cose.HeaderLabelCritical] = crit
	return nil
}

func parseProtectedHeaders(headers *cose.Headers, signInfo *signature.SignerInfo) error {
	protected := headers.Protected
	if protected == nil {
		return &signature.MalformedSignatureError{Msg: "missing cose envelope protected header"}
	}

	// crit
	labels, err := validateCritHeaders(protected)
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

	// signingTime, signingScheme
	signScheme, ok := protected[headerLabelSigningScheme].(string)
	if !ok {
		return &signature.MalformedSignatureError{Msg: "malformed signingScheme"}
	}
	switch signature.SigningScheme(signScheme) {
	case signature.SigningSchemeX509:
		signTime, ok := protected[headerLabelSigningTime].(int64)
		if !ok {
			return &signature.MalformedSignatureError{Msg: "malformed signingTime under notary.x509"}
		}
		signInfo.SignedAttributes.SigningTime = time.Unix(signTime, 0)
	case signature.SigningSchemeX509SigningAuthority:
		signTime, ok := protected[headerLabelAuthenticSigningTime].(int64)
		if !ok {
			return &signature.MalformedSignatureError{Msg: "malformed authenticSigningTime under notary.x509.signingAuthority"}
		}
		signInfo.SignedAttributes.SigningTime = time.Unix(signTime, 0)
	default:
		return &signature.MalformedSignatureError{Msg: "unsupported signingScheme: " + signScheme}
	}
	signInfo.SigningScheme = signature.SigningScheme(signScheme)

	// expiry
	exp, ok := protected[headerLabelExpiry].(int64)
	if !ok {
		return &signature.MalformedSignatureError{Msg: "malformed expiry"}
	}
	signInfo.SignedAttributes.Expiry = time.Unix(exp, 0)

	// extended attributes
	extendedAttributes := make(cose.ProtectedHeader)
	for k, v := range headers.Protected {
		extendedAttributes[k] = v
	}
	signInfo.SignedAttributes.ExtendedAttributes, err = getExtendedAttributes(labels, extendedAttributes)
	return err
}

// validateCritHeaders does a two-way check, namely:
// 1. validate that all critical headers are present in the protected bucket
// 2. validate that all required headers(as per spec) are marked critical
func validateCritHeaders(protected cose.ProtectedHeader) ([]interface{}, error) {
	// This ensures all critical headers are present in the protected bucket.
	labels, err := protected.Critical()
	if err != nil {
		return nil, err
	}
	// set of headers that must be marked as crit
	mustMarkedCrit := make(map[interface{}]struct{})
	mustMarkedCrit[headerLabelSigningScheme] = struct{}{}
	signScheme, ok := protected[headerLabelSigningScheme].(string)
	if !ok {
		return nil, &signature.MalformedSignatureError{Msg: "malformed signingScheme"}
	}
	if signature.SigningScheme(signScheme) == signature.SigningSchemeX509SigningAuthority {
		mustMarkedCrit[headerLabelAuthenticSigningTime] = struct{}{}
	}
	if _, ok := protected[headerLabelExpiry]; ok {
		mustMarkedCrit[headerLabelExpiry] = struct{}{}
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
		return nil, &signature.MalformedSignatureError{Msg: fmt.Sprintf("these required headers are not marked as critical: %v", headers)}
	}
	return labels, nil
}

func getExtendedAttributes(labels []interface{}, extendedAttributes cose.ProtectedHeader) ([]signature.Attribute, error) {
	intHeaders := []int64{cose.HeaderLabelAlgorithm, cose.HeaderLabelContentType, cose.HeaderLabelCritical}
	for _, h := range intHeaders {
		delete(extendedAttributes, h)
	}
	strHeaders := []string{headerLabelSigningTime, headerLabelExpiry, headerLabelSigningScheme, headerLabelAuthenticSigningTime}
	for _, h := range strHeaders {
		delete(extendedAttributes, h)
	}

	var extendedAttr []signature.Attribute
	for k, v := range extendedAttributes {
		key, ok := k.(string)
		if !ok {
			return nil, errors.New("extendedAttributes key requires string type")
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
