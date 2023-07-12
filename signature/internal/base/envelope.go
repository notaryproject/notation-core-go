// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package base

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	nx509 "github.com/notaryproject/notation-core-go/x509"
)

// Envelope represents a general envelope wrapping a raw signature and envelope
// in specific format.
// Envelope manipulates the common validation shared by internal envelopes.
type Envelope struct {
	signature.Envelope        // internal envelope in a specific format (e.g. COSE, JWS)
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
	content, err := e.Envelope.Content()
	if err != nil {
		return nil, err
	}

	if err := validateCertificateChain(
		content.SignerInfo.CertificateChain,
		&content.SignerInfo.SignedAttributes.SigningTime,
		content.SignerInfo.SignatureAlgorithm,
	); err != nil {
		return nil, err
	}

	e.Raw = raw
	return e.Raw, nil
}

// Verify performs integrity and other signature specification related
// validations.
// It returns envelope content containing the payload to be signed and
// SignerInfo object containing the information about the signature.
//
// Reference: https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#steps
func (e *Envelope) Verify() (*signature.EnvelopeContent, error) {
	// validation before the core verify process.
	if len(e.Raw) == 0 {
		return nil, &signature.SignatureNotFoundError{}
	}

	// core verify process.
	content, err := e.Envelope.Verify()
	if err != nil {
		return nil, err
	}

	// validation after the core verify process.
	if err = validateEnvelopeContent(content); err != nil {
		return nil, err
	}

	return content, nil
}

// Content returns the validated signature information and payload.
func (e *Envelope) Content() (*signature.EnvelopeContent, error) {
	if len(e.Raw) == 0 {
		return nil, &signature.SignatureNotFoundError{}
	}

	content, err := e.Envelope.Content()
	if err != nil {
		return nil, err
	}

	if err = validateEnvelopeContent(content); err != nil {
		return nil, err
	}

	return content, nil
}

// validateSignRequest performs basic set of validations on SignRequest struct.
func validateSignRequest(req *signature.SignRequest) error {
	if err := validatePayload(&req.Payload); err != nil {
		return &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	if err := validateSigningAndExpiryTime(req.SigningTime, req.Expiry); err != nil {
		return err
	}

	if req.Signer == nil {
		return &signature.InvalidSignRequestError{Msg: "signer is nil"}
	}

	if _, err := req.Signer.KeySpec(); err != nil {
		return err
	}

	return validateSigningSchema(req.SigningScheme)
}

// validateSigningSchema validates the schema.
func validateSigningSchema(schema signature.SigningScheme) error {
	if schema == "" {
		return &signature.InvalidSignRequestError{Msg: "SigningScheme not present"}
	}
	return nil
}

// validateEnvelopeContent validates the content which includes signerInfo and
// payload.
func validateEnvelopeContent(content *signature.EnvelopeContent) error {
	if err := validatePayload(&content.Payload); err != nil {
		return &signature.InvalidSignatureError{Msg: err.Error()}
	}
	return validateSignerInfo(&content.SignerInfo)
}

// validateSignerInfo performs basic set of validations on SignerInfo struct.
func validateSignerInfo(info *signature.SignerInfo) error {
	if len(info.Signature) == 0 {
		return &signature.InvalidSignatureError{Msg: "signature not present or is empty"}
	}

	if info.SignatureAlgorithm == 0 {
		return &signature.InvalidSignatureError{Msg: "SignatureAlgorithm is not present"}
	}

	signingTime := info.SignedAttributes.SigningTime
	if err := validateSigningAndExpiryTime(signingTime, info.SignedAttributes.Expiry); err != nil {
		return err
	}

	if err := validateSigningSchema(info.SignedAttributes.SigningScheme); err != nil {
		return err
	}

	return validateCertificateChain(
		info.CertificateChain,
		nil,
		info.SignatureAlgorithm,
	)
}

// validateSigningAndExpiryTime checks that signing time is within the valid
// range of time duration and expire time is valid.
func validateSigningAndExpiryTime(signingTime, expireTime time.Time) error {
	if signingTime.IsZero() {
		return &signature.InvalidSignatureError{Msg: "signing-time not present"}
	}

	if !expireTime.IsZero() && (expireTime.Before(signingTime) || expireTime.Equal(signingTime)) {
		return &signature.InvalidSignatureError{Msg: "expiry cannot be equal or before the signing time"}
	}
	return nil
}

// validatePayload performs validation of the payload.
func validatePayload(payload *signature.Payload) error {
	if len(payload.Content) == 0 {
		return errors.New("content not present")
	}

	return nil
}

// validateCertificateChain performs the validation of the certificate chain.
func validateCertificateChain(certChain []*x509.Certificate, signTime *time.Time, expectedAlg signature.Algorithm) error {
	if len(certChain) == 0 {
		return &signature.InvalidSignatureError{Msg: "certificate-chain not present or is empty"}
	}

	err := nx509.ValidateCodeSigningCertChain(certChain, signTime)
	if err != nil {
		return &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("certificate-chain is invalid, %s", err),
		}
	}

	signingAlg, err := getSignatureAlgorithm(certChain[0])
	if err != nil {
		return &signature.InvalidSignatureError{Msg: err.Error()}
	}
	if signingAlg != expectedAlg {
		return &signature.InvalidSignatureError{
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
