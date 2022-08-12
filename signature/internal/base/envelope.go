package base

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	nx509 "github.com/notaryproject/notation-core-go/x509"
)

// Envelope represents a general envelope wrapping a raw signature and envelope
// in specific format.
type Envelope struct {
	signature.Envelope        // internal envelope in a specific format(COSE/JWS)
	Raw                []byte // raw signature
}

// Sign generates signature using given SignRequest.
func (e *Envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	err := validateSignRequest(req)
	if err != nil {
		return nil, err
	}

	e.Raw, err = e.Envelope.Sign(req)
	if err != nil {
		return nil, err
	}
	return e.Raw, nil
}

// Verify performs integrity and other signature specification related validations.
// Returns the payload to be signed and SignerInfo object containing the information
// about the signature.
func (e *Envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	if err := e.preVerifyValidation(); err != nil {
		return nil, nil, err
	}

	return e.Envelope.Verify()
}

// Payload returns the payload to be signed.
func (e *Envelope) Payload() (*signature.Payload, error) {
	if len(e.Raw) == 0 {
		return nil, &signature.MalformedSignatureError{Msg: "raw signature is empty"}
	}
	payload, err := e.Envelope.Payload()
	if err != nil {
		return nil, err
	}

	if err = validatePayload(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// SignerInfo returns information about the Signature envelope.
func (e *Envelope) SignerInfo() (*signature.SignerInfo, error) {
	if len(e.Raw) == 0 {
		return nil, &signature.MalformedSignatureError{Msg: "raw signature is empty"}
	}

	signerInfo, err := e.Envelope.SignerInfo()
	if err != nil {
		return nil, &signature.MalformedSignatureError{
			Msg: fmt.Sprintf("signature envelope format is malformed. error: %s", err),
		}
	}

	if err := validateSignerInfo(signerInfo); err != nil {
		return nil, err
	}

	if err := e.validatePayload(); err != nil {
		return nil, err
	}

	return signerInfo, nil
}

// preVerifyValidation performs validation before verification of internal envelope.
func (e *Envelope) preVerifyValidation() error {
	if len(e.Raw) == 0 {
		return &signature.MalformedSignatureError{}
	}

	return e.validatePayload()
}

// validatePayload performs validation of the payload.
func (e *Envelope) validatePayload() error {
	payload, err := e.Envelope.Payload()
	if err != nil {
		return err
	}

	return validatePayload(payload)
}

// validateSignRequest performs basic set of validations on SignRequest struct.
func validateSignRequest(req *signature.SignRequest) error {
	if err := validatePayload(&req.Payload); err != nil {
		return err
	}

	if err := validateSigningTime(req.SigningTime, req.Expiry); err != nil {
		return err
	}

	if len(req.Payload.Content) == 0 {
		return &signature.MalformedSignatureError{Msg: "payload not present"}
	}

	if req.Signer == nil {
		return &signature.MalformedSignatureError{Msg: "signer is nil"}
	}

	certs, err := req.Signer.CertificateChain()
	if err != nil {
		return err
	}

	keySpec, err := req.Signer.KeySpec()
	if err != nil {
		return err
	}

	return validateCertificateChain(certs, req.SigningTime, keySpec.SignatureAlgorithm())
}

// validateSignerInfo performs basic set of validations on SignerInfo struct.
func validateSignerInfo(info *signature.SignerInfo) error {
	if len(info.Signature) == 0 {
		return &signature.MalformedSignatureError{Msg: "signature not present or is empty"}
	}

	if info.SignatureAlgorithm == 0 {
		return &signature.MalformedSignatureError{Msg: "SignatureAlgorithm is not present"}
	}

	signingTime := info.SignedAttributes.SigningTime
	if err := validateSigningTime(signingTime, info.SignedAttributes.Expiry); err != nil {
		return err
	}

	return validateCertificateChain(
		info.CertificateChain,
		signingTime,
		info.SignatureAlgorithm,
	)
}

// validateSigningTime checks that sigining time is within the valid range of
// time duration.
func validateSigningTime(signingTime, expireTime time.Time) error {
	if signingTime.IsZero() {
		return &signature.MalformedSignatureError{Msg: "signing-time not present"}
	}

	if !expireTime.IsZero() && (expireTime.Before(signingTime) || expireTime.Equal(signingTime)) {
		return &signature.MalformedSignatureError{Msg: "expiry cannot be equal or before the signing time"}
	}
	return nil
}

// validatePayload performs validation of the payload.
func validatePayload(payload *signature.Payload) error {
	if payload.ContentType != signature.MediaTypePayloadV1 {
		return &signature.MalformedSignatureError{
			Msg: fmt.Sprintf("payload content type: {%s} not supported", payload.ContentType),
		}
	}

	if len(payload.Content) == 0 {
		return &signature.MalformedSignatureError{Msg: "content not present"}
	}

	return nil
}

// validateCertificateChain performs the validation of the certificate chain.
func validateCertificateChain(certChain []*x509.Certificate, signTime time.Time, expectedAlg signature.Algorithm) error {
	if len(certChain) == 0 {
		return &signature.MalformedSignatureError{Msg: "certificate-chain not present or is empty"}
	}

	err := nx509.ValidateCodeSigningCertChain(certChain, signTime)
	if err != nil {
		return &signature.MalformedSignatureError{
			Msg: fmt.Sprintf("certificate-chain is invalid, %s", err),
		}
	}

	signingAlg, err := getSignatureAlgorithm(certChain[0])
	if err != nil {
		return &signature.MalformedSignatureError{Msg: err.Error()}
	}
	if signingAlg != expectedAlg {
		return &signature.MalformedSignatureError{
			Msg: "mismatch between signature algorithm derived from signing certificate and signing algorithm specified",
		}
	}

	return nil
}

// getSignatureAlgorithm picks up a recommended signing algorithm for given certificate.
func getSignatureAlgorithm(signingCert *x509.Certificate) (signature.Algorithm, error) {
	keySpec, err := signature.ExtractKeySpec(signingCert)
	if err != nil {
		return 0, err
	}

	return keySpec.SignatureAlgorithm(), nil
}
