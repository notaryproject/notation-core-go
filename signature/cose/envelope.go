package cose

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
	"github.com/veraison/go-cose"
)

// MediaTypeEnvelope is the COSE signature envelope blob mediaType.
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
	headerLabelSigningScheme        = "io.cncf.notary.signingScheme"
	headerLabelSigningTime          = "io.cncf.notary.signingTime"
	headerLabelAuthenticSigningTime = "io.cncf.notary.authenticSigningTime"
)

// Unprotected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerLabelTimeStampSignature = "io.cncf.notary.timestampSignature"
	headerLabelSigningAgent       = "io.cncf.notary.signingAgent"
)

// Map of cose.Algorithm to signature.Algorithm
var coseAlgSignatureAlgMap = map[cose.Algorithm]signature.Algorithm{
	cose.AlgorithmPS256: signature.AlgorithmPS256,
	cose.AlgorithmPS384: signature.AlgorithmPS384,
	cose.AlgorithmPS512: signature.AlgorithmPS512,
	cose.AlgorithmES256: signature.AlgorithmES256,
	cose.AlgorithmES384: signature.AlgorithmES384,
	cose.AlgorithmES512: signature.AlgorithmES512,
}

// Map of signingScheme to signingTime header label
var signingSchemeTimeLabelMap = map[signature.SigningScheme]string{
	signature.SigningSchemeX509:                 headerLabelSigningTime,
	signature.SigningSchemeX509SigningAuthority: headerLabelAuthenticSigningTime,
}

// signer interface is a cose.Signer with certificate chain fetcher.
type signer interface {
	cose.Signer
	CertificateChain() []*x509.Certificate
}

// remoteSigner implements signer interface.
// It is used in Sign process when base's Sign implementation is desired.
type remoteSigner struct {
	base  signature.Signer
	alg   cose.Algorithm
	certs []*x509.Certificate
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

// Algorithm implements cose.Signer interface.
func (signer *remoteSigner) Algorithm() cose.Algorithm {
	return signer.alg
}

// Sign implements cose.Signer interface.
func (signer *remoteSigner) Sign(rand io.Reader, payload []byte) ([]byte, error) {
	signature, certs, err := signer.base.Sign(payload)
	if err != nil {
		return nil, err
	}
	signer.certs = certs
	return signature, nil
}

// CertificateChain implements signer interface.
func (signer *remoteSigner) CertificateChain() []*x509.Certificate {
	return signer.certs
}

type localSigner struct {
	cose.Signer
	certs []*x509.Certificate
}

func newLocalSigner(base signature.LocalSigner) (*localSigner, error) {
	key := base.PrivateKey()
	if cryptoSigner, ok := key.(crypto.Signer); ok {
		certs, err := base.CertificateChain()
		if err != nil {
			return nil, err
		}
		keySpec, err := base.KeySpec()
		if err != nil {
			return nil, err
		}
		alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
		if err != nil {
			return nil, err
		}
		coseSigner, err := cose.NewSigner(alg, cryptoSigner)
		if err != nil {
			return nil, err
		}
		return &localSigner{
			Signer: coseSigner,
			certs:  certs,
		}, nil
	}
	return nil, &signature.UnsupportedSigningKeyError{}
}

// CertificateChain implements signer interface.
func (signer *localSigner) CertificateChain() []*x509.Certificate {
	return signer.certs
}

type envelope struct {
	base *cose.Sign1Message
}

// NewEnvelope initializes an empty COSE signature envelope.
func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{},
	}
}

// ParseEnvelope parses envelopeBytes to a COSE signature envelope.
func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(envelopeBytes); err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	return &base.Envelope{
		Envelope: &envelope{
			base: &msg,
		},
		Raw: envelopeBytes,
	}, nil
}

// Sign implements signature.Envelope interface.
// On success, this function returns the COSE signature envelope byte slice.
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	// get built-in signer from go-cose or remote signer based on req.Signer
	signer, err := getSigner(req.Signer)
	if err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// prepare COSE_Sign1 message
	msg := cose.NewSign1Message()

	// generate protected headers of COSE envelope
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())
	if err := generateProtectedHeaders(req, msg.Headers.Protected); err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// generate payload of COSE envelope
	msg.Headers.Protected[cose.HeaderLabelContentType] = req.Payload.ContentType
	msg.Payload = req.Payload.Content

	// core sign process, generate signature of COSE envelope
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// generate unprotected headers of COSE envelope
	generateUnprotectedHeaders(req, signer, msg.Headers.Unprotected)

	// TODO: needs to add headerKeyTimeStampSignature.

	// encode Sign1Message into COSE_Sign1_Tagged object
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	e.base = msg
	return encoded, nil
}

// Verify implements signature.Envelope interface.
// Note: Verfiy only verifies integrity of the given COSE envelope.
func (e *envelope) Verify() (*signature.EnvelopeContent, error) {
	// sanity check
	if e.base == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}

	certs, ok := e.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([]interface{})
	if !ok || len(certs) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "certificate chain is not present"}
	}
	certRaw, ok := certs[0].([]byte)
	if !ok {
		return nil, &signature.InvalidSignatureError{Msg: "COSE envelope malformed leaf certificate"}
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: "malformed leaf certificate"}
	}

	// core verify process, verify integrity of COSE envelope
	publicKeyAlg, err := getSignatureAlgorithm(cert)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	verifier, err := cose.NewVerifier(publicKeyAlg, cert.PublicKey)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	err = e.base.Verify(nil, verifier)
	if err != nil {
		return nil, &signature.SignatureIntegrityError{Err: err}
	}

	// extract content
	return e.Content()
}

// Content implements signature.Envelope interface.
func (e *envelope) Content() (*signature.EnvelopeContent, error) {
	// sanity check
	if e.base == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}

	payload, err := e.payload()
	if err != nil {
		return nil, err
	}
	signerInfo, err := e.signerInfo()
	if err != nil {
		return nil, err
	}
	return &signature.EnvelopeContent{
		SignerInfo: *signerInfo,
		Payload:    *payload,
	}, nil
}

// Given a COSE envelope, extracts its signature.Payload.
func (e *envelope) payload() (*signature.Payload, error) {
	cty, ok := e.base.Headers.Protected[cose.HeaderLabelContentType]
	if !ok {
		return nil, &signature.InvalidSignatureError{Msg: "missing content type"}
	}
	var contentType string
	if contentType, ok = cty.(string); !ok {
		return nil, &signature.InvalidSignatureError{Msg: "content type should be of 'tstr' type"}
	}
	return &signature.Payload{
		ContentType: contentType,
		Content:     e.base.Payload,
	}, nil
}

// Given a COSE envelope, extracts its signature.SignerInfo.
func (e *envelope) signerInfo() (*signature.SignerInfo, error) {
	var signerInfo signature.SignerInfo

	// parse signature of COSE envelope, populate signerInfo.Signature
	sig := e.base.Signature
	if len(sig) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "signature missing in COSE envelope"}
	}
	signerInfo.Signature = sig

	// parse protected headers of COSE envelope and populate related
	// signerInfo fields
	err := parseProtectedHeaders(e.base.Headers.Protected, &signerInfo)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	// parse unprotected headers of COSE envelope
	certs, ok := e.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([]interface{})
	if !ok || len(certs) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "certificate chain is not present"}
	}
	var certChain []*x509.Certificate
	for _, c := range certs {
		certRaw, ok := c.([]byte)
		if !ok {
			return nil, &signature.InvalidSignatureError{Msg: "certificate chain is not present"}
		}
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			return nil, &signature.InvalidSignatureError{Msg: err.Error()}
		}
		certChain = append(certChain, cert)
	}
	// populate signerInfo.CertificateChain
	signerInfo.CertificateChain = certChain

	// populate signerInfo.UnsignedAttributes.SigningAgent
	if h, ok := e.base.Headers.Unprotected[headerLabelSigningAgent].(string); ok {
		signerInfo.UnsignedAttributes.SigningAgent = h
	}

	// TODO: needs to add headerKeyTimeStampSignature.

	return &signerInfo, nil
}

// getSignatureAlgorithm picks up a recommended signing algorithm for given
// certificate.
func getSignatureAlgorithm(signingCert *x509.Certificate) (cose.Algorithm, error) {
	keySpec, err := signature.ExtractKeySpec(signingCert)
	if err != nil {
		return 0, err
	}
	return getSignatureAlgorithmFromKeySpec(keySpec)
}

// getSignatureAlgorithmFromKeySpec ensures the signing algorithm satisfies
// algorithm requirements.
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
			return 0, &signature.UnsupportedSigningKeyError{Msg: fmt.Sprintf("RSA: key size %d not supported", keySpec.Size)}
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
			return 0, &signature.UnsupportedSigningKeyError{Msg: fmt.Sprintf("EC: key size %d not supported", keySpec.Size)}
		}
	default:
		return 0, &signature.UnsupportedSigningKeyError{Msg: "key type not supported"}
	}
}

// getSigner returns the built-in implementation of cose.Signer from go-cose
// or a remote signer implementation of cose.Signer.
func getSigner(signer signature.Signer) (signer, error) {
	if localSigner, ok := signer.(signature.LocalSigner); ok {
		return newLocalSigner(localSigner)
	}
	return newRemoteSigner(signer)
}

// generateProtectedHeaders creates Protected Headers of the COSE envelope
// during Sign process.
func generateProtectedHeaders(req *signature.SignRequest, protected cose.ProtectedHeader) error {
	// signingScheme
	crit := []interface{}{headerLabelSigningScheme}
	protected[headerLabelSigningScheme] = string(req.SigningScheme)

	// signingTime/authenticSigningTime
	signingTimeLabel, ok := signingSchemeTimeLabelMap[req.SigningScheme]
	if !ok {
		return &signature.InvalidSignRequestError{Msg: "signing scheme: require notary.x509 or notary.x509.signingAuthority"}
	}
	protected[signingTimeLabel] = req.SigningTime.Unix()
	if signingTimeLabel == headerLabelAuthenticSigningTime {
		crit = append(crit, headerLabelAuthenticSigningTime)
	}

	// expiry
	if !req.Expiry.IsZero() {
		crit = append(crit, headerLabelExpiry)
		protected[headerLabelExpiry] = req.Expiry.Unix()
	}

	// extended attributes
	for _, elm := range req.ExtendedSignedAttributes {
		if _, ok := protected[elm.Key]; ok {
			return &signature.InvalidSignRequestError{Msg: fmt.Sprintf("%q already exists in the protected header", elm.Key)}
		}
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
		protected[elm.Key] = elm.Value
	}

	// critical headers
	protected[cose.HeaderLabelCritical] = crit

	return nil
}

// generateUnprotectedHeaders creates Unprotected Headers of the COSE envelope
// during Sign process.
func generateUnprotectedHeaders(req *signature.SignRequest, signer signer, unprotected cose.UnprotectedHeader) {
	// signing agent
	if req.SigningAgent != "" {
		unprotected[headerLabelSigningAgent] = req.SigningAgent
	}

	// certChain
	certs := signer.CertificateChain()
	certChain := make([]interface{}, len(certs))
	for i, c := range certs {
		certChain[i] = c.Raw
	}
	unprotected[cose.HeaderLabelX5Chain] = certChain
}

// parseProtectedHeaders parses COSE envelope's protected headers and
// populates signature.SignerInfo.
func parseProtectedHeaders(protected cose.ProtectedHeader, signerInfo *signature.SignerInfo) error {
	// validate critical headers and return extendedAttributeKeys
	extendedAttributeKeys, err := validateCritHeaders(protected)
	if err != nil {
		return err
	}

	// populate signerInfo.SignatureAlgorithm
	alg, err := protected.Algorithm()
	if err != nil {
		return err
	}
	sigAlg, ok := coseAlgSignatureAlgMap[alg]
	if !ok {
		return &signature.InvalidSignatureError{Msg: "signature algorithm not supported: " + strconv.Itoa(int(alg))}
	}
	signerInfo.SignatureAlgorithm = sigAlg

	// populate signerInfo.SignedAttributes.SigningScheme
	signingSchemeString, ok := protected[headerLabelSigningScheme].(string)
	if !ok {
		return &signature.InvalidSignatureError{Msg: "invalid signingScheme"}
	}
	signingScheme := signature.SigningScheme(signingSchemeString)
	signerInfo.SignedAttributes.SigningScheme = signingScheme

	// populate signerInfo.SignedAttributes.SigningTime
	signingTimeLabel, ok := signingSchemeTimeLabelMap[signingScheme]
	if !ok {
		return &signature.InvalidSignatureError{Msg: "unsupported signingScheme: " + signingSchemeString}
	}
	signingTime, ok := protected[signingTimeLabel].(int64)
	if !ok {
		return &signature.InvalidSignatureError{Msg: "invalid signingTime under signing scheme: " + signingSchemeString}
	}
	signerInfo.SignedAttributes.SigningTime = time.Unix(signingTime, 0)

	// populate signerInfo.SignedAttributes.Expiry
	if exp, ok := protected[headerLabelExpiry]; ok {
		expiry, ok := exp.(int64)
		if !ok {
			return &signature.InvalidSignatureError{Msg: "expiry requires int64 type"}
		}
		signerInfo.SignedAttributes.Expiry = time.Unix(expiry, 0)
	}

	// populate signerInfo.SignedAttributes.ExtendedAttributes
	signerInfo.SignedAttributes.ExtendedAttributes, err = generateExtendedAttributes(extendedAttributeKeys, protected)
	return err
}

// validateCritHeaders does a two-way check, namely:
// 1. validate that all critical headers are present in the protected bucket
// 2. validate that all required headers(as per spec) are marked critical
// Returns list of extended attribute keys
func validateCritHeaders(protected cose.ProtectedHeader) ([]interface{}, error) {
	// This ensures all critical headers are present in the protected bucket.
	labels, err := protected.Critical()
	if err != nil {
		return nil, err
	}

	// set of headers that must be marked as crit
	mustMarkedCrit := make(map[interface{}]struct{})
	mustMarkedCrit[headerLabelSigningScheme] = struct{}{}
	signingScheme, ok := protected[headerLabelSigningScheme].(string)
	if !ok {
		return nil, &signature.InvalidSignatureError{Msg: "invalid signingScheme"}
	}
	if signature.SigningScheme(signingScheme) == signature.SigningSchemeX509SigningAuthority {
		mustMarkedCrit[headerLabelAuthenticSigningTime] = struct{}{}
	}
	if _, ok := protected[headerLabelExpiry]; ok {
		mustMarkedCrit[headerLabelExpiry] = struct{}{}
	}

	// validate that all required headers(as per spec) are marked as critical
	for _, label := range labels {
		delete(mustMarkedCrit, label)
	}
	if len(mustMarkedCrit) != 0 {
		headers := make([]interface{}, 0, len(mustMarkedCrit))
		for k := range mustMarkedCrit {
			headers = append(headers, k)
		}
		return nil, &signature.InvalidSignatureError{Msg: fmt.Sprintf("these required headers are not marked as critical: %v", headers)}
	}

	// fetch all the extended signed attributes
	systemHeaders := []interface{}{cose.HeaderLabelAlgorithm, cose.HeaderLabelCritical, cose.HeaderLabelContentType,
		headerLabelExpiry, headerLabelSigningScheme, headerLabelSigningTime, headerLabelAuthenticSigningTime}
	var extendedAttributeKeys []interface{}
	for label := range protected {
		if contains(systemHeaders, label) {
			continue
		}
		extendedAttributeKeys = append(extendedAttributeKeys, label)
	}

	return extendedAttributeKeys, nil
}

// generateExtendedAttributes generates []signature.Attribute during
// SignerInfo process.
func generateExtendedAttributes(extendedAttributeKeys []interface{}, protected cose.ProtectedHeader) ([]signature.Attribute, error) {
	criticalHeaders, ok := protected[cose.HeaderLabelCritical].([]interface{})
	if !ok {
		return nil, &signature.InvalidSignatureError{Msg: "invalid critical headers"}
	}
	var extendedAttr []signature.Attribute
	for _, key := range extendedAttributeKeys {
		extendedAttr = append(extendedAttr, signature.Attribute{
			Key:      key,
			Critical: contains(criticalHeaders, key),
			Value:    protected[key],
		})
	}
	return extendedAttr, nil
}

// contains checks if e is in s
func contains(s []interface{}, e interface{}) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
