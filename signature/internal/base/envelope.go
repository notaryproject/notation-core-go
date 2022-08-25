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
// Envelope manipulates the common validation shared by internal envelopes.
type Envelope struct {
	signature.Envelope        // internal envelope in a specific format(e.g. Cose, JWS)
	Raw                []byte // raw signature
}

// Sign generates signature in terms of given SignRequest.
//
// Reference: https://github.com/notaryproject/notaryproject/blob/main/signing-and-verification-workflow.md#signing-steps
func (e *Envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	// Canonicalize request.
	req.SigningTime = req.SigningTime.Truncate(time.Second)
	req.Expiry = req.Expiry.Truncate(time.Second)
	err := validateSignRequest(req)
	if err != nil {
		return nil, err
	}

	raw, err := e.Envelope.Sign(req)
	if err != nil {
		return nil, err
	}

	// validate certificate chain
	signerInfo, err := e.Envelope.SignerInfo()
	if err != nil {
		return nil, err
	}

	if err := validateCertificateChain(
		signerInfo.CertificateChain,
		signerInfo.SignedAttributes.SigningTime,
		signerInfo.SignatureAlgorithm,
	); err != nil {
		return nil, err
	}

	e.Raw = raw
	return e.Raw, nil
}

// Verify performs integrity and other signature specification related
// validations.
// It returns the payload to be signed and SignerInfo object containing the
// information about the signature.
//
// Reference: https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#steps
func (e *Envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	// validation before the core verify process.
	if len(e.Raw) == 0 {
		return nil, nil, &signature.MalformedSignatureError{}
	}

	// core verify process.
	payload, signerInfo, err := e.Envelope.Verify()
	if err != nil {
		return nil, nil, err
	}

	// validation after the core verify process.
	if err = validatePayload(payload); err != nil {
		return nil, nil, err
	}

	if err = validateSignerInfo(signerInfo); err != nil {
		return nil, nil, err
	}

	return payload, signerInfo, nil
}

// Payload returns the validated payload to be signed.
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

// SignerInfo returns validated information about the signature envelope.
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

	return signerInfo, nil
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

	if req.Signer == nil {
		return &signature.MalformedSignatureError{Msg: "signer is nil"}
	}

	_, err := req.Signer.KeySpec()
	return err
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

// validateSigningTime checks that signing time is within the valid range of
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
	switch payload.ContentType {
	case signature.MediaTypePayloadV1:
		if len(payload.Content) == 0 {
			return &signature.MalformedSignatureError{Msg: "content not present"}
		}
	default:
		return &signature.MalformedSignatureError{
			Msg: fmt.Sprintf("payload content type: {%s} not supported", payload.ContentType),
		}
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
			Msg: fmt.Sprintf("mismatch between signature algorithm derived from signing certificate (%v) and signing algorithm specified (%vs)", signingAlg, expectedAlg),
		}
	}

	return nil
}

// getSignatureAlgorithm picks up a recommended signing algorithm for given
// certificate.
func getSignatureAlgorithm(signingCert *x509.Certificate) (signature.Algorithm, error) {
	keySpec, err := signature.ExtractKeySpec(signingCert)
	if err != nil {
		return 0, err
	}

	return keySpec.SignatureAlgorithm(), nil
}
