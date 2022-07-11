package signer

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	nx509 "github.com/notaryproject/notation-core-go/x509"
)

// SignerInfo represents a parsed signature envelope that is agnostic to signature envelope format.
type SignerInfo struct {
	Payload            []byte
	PayloadContentType PayloadContentType
	SignedAttributes   SignedAttributes
	UnsignedAttributes UnsignedAttributes
	SignatureAlgorithm SignatureAlgorithm
	CertificateChain   []*x509.Certificate
	Signature          []byte
	SigningScheme      SigningScheme
	TimestampSignature []byte
}

// SignedAttributes represents signed metadata in the Signature envelope
type SignedAttributes struct {
	SigningTime                  time.Time
	Expiry                       time.Time
	VerificationPlugin           string
	VerificationPluginMinVersion string
	ExtendedAttributes           []Attribute
}

// UnsignedAttributes represents unsigned metadata in the Signature envelope
type UnsignedAttributes struct {
	SigningAgent string
}

// SignRequest is used to generate Signature.
type SignRequest struct {
	Payload                      []byte
	PayloadContentType           PayloadContentType
	SignatureProvider            SignatureProvider
	SigningTime                  time.Time
	Expiry                       time.Time
	ExtendedSignedAttrs          []Attribute
	SigningAgent                 string
	SigningScheme                SigningScheme
	VerificationPlugin           string
	VerificationPluginMinVersion string  // TODO: Implement SimVer structure
}

// Attribute represents metadata in the Signature envelope
type Attribute struct {
	Key      string
	Critical bool
	Value    interface{}
}

// SignatureProvider is used to sign bytes generated after creating Signature envelope.
type SignatureProvider interface {
	Sign([]byte) ([]byte, []*x509.Certificate, error)
	KeySpec() (KeySpec, error)
}

// SignatureEnvelope provides functions to generate signature and verify signature.
type SignatureEnvelope struct {
	rawSignatureEnvelope []byte
	internalEnvelope     internalSignatureEnvelope
}

// Contains a set of common methods that every Signature envelope format must implement.
type internalSignatureEnvelope interface {
	// validateIntegrity validates the integrity of given Signature envelope.
	validateIntegrity() error
	// getSignerInfo returns the information stored in the Signature envelope and doesn't perform integrity verification.
	getSignerInfo() (*SignerInfo, error)
	// signPayload created Signature envelope.
	signPayload(SignRequest) ([]byte, error)
}

// Verify performs integrity and other signature specification related validations
// Returns the SignerInfo object containing the information about the signature.
func (s *SignatureEnvelope) Verify() (*SignerInfo, error) {
	if len(s.rawSignatureEnvelope) == 0 {
		return nil, SignatureNotFoundError{}
	}

	integrityError := s.internalEnvelope.validateIntegrity()
	if integrityError != nil {
		return nil, integrityError
	}

	singerInfo, singerInfoErr := s.GetSignerInfo()
	if singerInfoErr != nil {
		return nil, singerInfoErr
	}

	return singerInfo, nil
}

// Sign generates Signature using given SignRequest.
func (s *SignatureEnvelope) Sign(req SignRequest) ([]byte, error) {
	// Sanitize request
	req.SigningTime = req.SigningTime.Truncate(time.Second)
	req.Expiry = req.Expiry.Truncate(time.Second)

	// validate request
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}

	// perform signature generation
	sig, err := s.internalEnvelope.signPayload(req)
	if err != nil {
		return nil, err
	}

	s.rawSignatureEnvelope = sig
	return sig, nil
}

// GetSignerInfo returns information about the Signature envelope
func (s SignatureEnvelope) GetSignerInfo() (*SignerInfo, error) {
	if len(s.rawSignatureEnvelope) == 0 {
		return nil, SignatureNotFoundError{}
	}

	signInfo, err := s.internalEnvelope.getSignerInfo()
	if err != nil {
		return nil, MalformedSignatureError{msg: fmt.Sprintf("signature envelope format is malformed. error: %s", err)}
	}

	if err := validateSignerInfo(signInfo); err != nil {
		return nil, err
	}
	return signInfo, nil
}

// validateSignerInfo performs basic set of validations on SignerInfo struct.
func validateSignerInfo(info *SignerInfo) error {
	if len(info.Signature) == 0 {
		return MalformedSignatureError{msg: "signature not present or is empty"}
	}

	if info.SignatureAlgorithm == "" {
		return MalformedSignRequestError{msg: "SignatureAlgorithm is not present"}
	}

	errorFunc := func(s string) error {
		return MalformedSignatureError{msg: s}
	}

	sAttr := info.SignedAttributes
	if err := validate(info.Payload, info.PayloadContentType, sAttr.VerificationPlugin, sAttr.VerificationPluginMinVersion,
		sAttr.SigningTime, sAttr.Expiry, info.SigningScheme, errorFunc); err != nil {
		return err
	}

	if err := validateCertificateChain(info.CertificateChain, info.SignedAttributes.SigningTime, info.SignatureAlgorithm, errorFunc); err != nil {
		return err
	}

	return nil
}

// validateSignRequest performs basic set of validations on SignRequest struct.
func validateSignRequest(req SignRequest) error {
	errorFunc := func(s string) error {
		return MalformedSignRequestError{msg: s}
	}

	if err := validate(req.Payload, req.PayloadContentType, req.VerificationPlugin, req.VerificationPluginMinVersion,
		req.SigningTime, req.Expiry, req.SigningScheme, errorFunc); err != nil {
		return err
	}

	if len(req.Payload) == 0 {
		return MalformedSignRequestError{msg: "payload not present"}
	}

	if req.SignatureProvider == nil {
		return MalformedSignRequestError{msg: "SignatureProvider is nil"}
	}

	return nil
}

func validateCertificateChain(certChain []*x509.Certificate, signTime time.Time, expectedAlg SignatureAlgorithm, f func(string) error) error {
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

func validate(payload []byte, payloadCty PayloadContentType, vPlugin, vPluginVersion string, signTime, expTime time.Time, scheme SigningScheme, f func(string) error) error {
	if len(payload) == 0 {
		return f("payload not present")
	}

	if payloadCty == "" {
		return f("payload content type not present or is empty")
	}

	if signTime.IsZero() {
		return f("signing-time not present")
	}

	if !expTime.IsZero() && (expTime.Before(signTime) || expTime.Equal(signTime)) {
		return f("expiry cannot be equal or before the signing time")
	}

	if scheme == "" {
		return f("SigningScheme not present")
	}

	if vPlugin != "" && strings.TrimSpace(vPlugin) == "" {
		return MalformedSignRequestError{msg: "VerificationPlugin cannot contain only whitespaces"}
	}

	if vPluginVersion != "" && strings.TrimSpace(vPluginVersion) == "" {
		return MalformedSignRequestError{msg: "VerificationPluginMinVersion cannot contain only whitespaces"}
	}

	if vPlugin == "" && vPluginVersion != "" {
		return MalformedSignRequestError{msg: "VerificationPluginMinVersion cannot be used without VerificationPlugin"}
	}

	return nil
}

// NewSignatureEnvelopeFromBytes is used for signature verification workflow
func NewSignatureEnvelopeFromBytes(envelopeBytes []byte, envelopeMediaType SignatureMediaType) (*SignatureEnvelope, error) {
	switch envelopeMediaType {
	case MediaTypeJWSJson:
		internal, err := newJWSEnvelopeFromBytes(envelopeBytes)
		if err != nil {
			return nil, MalformedArgumentError{"envelopeBytes", err}
		}
		return &SignatureEnvelope{envelopeBytes, internal}, nil
	default:
		return nil, UnsupportedSignatureFormatError{mediaType: string(envelopeMediaType)}
	}
}

// NewSignatureEnvelope is used for signature generation workflow
func NewSignatureEnvelope(envelopeMediaType SignatureMediaType) (*SignatureEnvelope, error) {
	switch envelopeMediaType {
	case MediaTypeJWSJson:
		return &SignatureEnvelope{internalEnvelope: &jwsEnvelope{}}, nil
	default:
		return nil, UnsupportedSignatureFormatError{mediaType: string(envelopeMediaType)}
	}
}

// VerifyAuthenticity verifies the certificate chain in the given SignerInfo with one of the trusted certificates
// and returns a certificate that matches with one of the certificates in the SignerInfo.
func VerifyAuthenticity(signerInfo *SignerInfo, trustedCerts []*x509.Certificate) (*x509.Certificate, error) {
	if len(trustedCerts) == 0 {
		return nil, MalformedArgumentError{param: "trustedCerts"}
	}

	if signerInfo == nil {
		return nil, MalformedArgumentError{param: "signerInfo"}
	}

	for _, trust := range trustedCerts {
		for _, sig := range signerInfo.CertificateChain {
			if trust.Equal(sig) {
				return trust, nil
			}
		}
	}
	return nil, SignatureAuthenticityError{}
}
