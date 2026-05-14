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

// Package pkcs7 provides a PKCS#7/CMS signature envelope for dm-verity
// signing.
package pkcs7

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/notaryproject/notation-core-go/signature"
	gopkcs7 "go.mozilla.org/pkcs7"
)

// ErrDetachedNotVerifiable is returned by Envelope.Verify. The dm-verity
// PKCS#7 envelope is detached and Envelope.Verify takes no payload, so it
// cannot perform cryptographic verification. Verify the dm-verity root
// hash out-of-band.
var ErrDetachedNotVerifiable = errors.New("PKCS#7 dm-verity envelope is detached; verify against the dm-verity root hash out-of-band")

// MediaTypeEnvelope is the PKCS#7 signature envelope media type.
const MediaTypeEnvelope = "application/pkcs7-signature"

func init() {
	if err := signature.RegisterEnvelopeType(MediaTypeEnvelope, NewEnvelope, ParseEnvelope); err != nil {
		panic(err)
	}
}

// envelope holds a parsed PKCS#7 signature. raw is canonical; certs and
// sigBytes are caches derived from raw.
type envelope struct {
	raw      []byte
	certs    []*x509.Certificate
	sigBytes []byte
}

// NewEnvelope creates a new PKCS#7 envelope.
//
// The dm-verity profile requires a SignerInfo with no signed attributes,
// so this envelope is not wrapped with base.Envelope (which injects a
// signing-time signed attribute).
func NewEnvelope() signature.Envelope {
	return &envelope{}
}

// ParseEnvelope parses PKCS#7 DER bytes into an envelope.
func ParseEnvelope(envelopeBytes []byte) (env signature.Envelope, err error) {
	// Convert any panic from the underlying parser to a typed error.
	defer func() {
		if r := recover(); r != nil {
			env = nil
			err = &signature.InvalidSignatureError{Msg: fmt.Sprintf("malformed PKCS#7 envelope: %v", r)}
		}
	}()
	p7, err := gopkcs7.Parse(envelopeBytes)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	// dm-verity profile: exactly one signer with a non-empty signature.
	if len(p7.Signers) != 1 {
		return nil, &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("dm-verity PKCS#7 envelope requires exactly one signer; got %d", len(p7.Signers)),
		}
	}
	sigBytes := p7.Signers[0].EncryptedDigest
	if len(sigBytes) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "dm-verity PKCS#7 envelope has empty signature"}
	}

	return &envelope{
		raw:      envelopeBytes,
		certs:    p7.Certificates,
		sigBytes: sigBytes,
	}, nil
}

// Sign implements signature.Envelope for the dm-verity profile: RSA-2048 +
// SHA-256 + RSASSA-PKCS#1 v1.5, detached, no signed attributes. The actual
// signing is done by req.Signer; gopkcs7 only wraps the resulting bytes in
// CMS SignedData. Sign verifies the signer's output against certs[0]
// before wrapping.
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	if err := validateSignRequest(req); err != nil {
		return nil, err
	}

	sig, certs, err := req.Signer.Sign(req.Payload.Content)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: fmt.Sprintf("signing failed: %v", err)}
	}
	if err := verifySignerOutput(req.Payload.Content, sig, certs); err != nil {
		return nil, err
	}

	sd, err := gopkcs7.NewSignedData(req.Payload.Content)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	// dm-verity profile: SHA-256 digest, RSASSA-PKCS#1 v1.5 signature,
	// no signed attributes, detached content.
	sd.SetDigestAlgorithm(gopkcs7.OIDDigestAlgorithmSHA256)
	sd.SetEncryptionAlgorithm(gopkcs7.OIDEncryptionAlgorithmRSA)
	adapter := &signerAdapter{sig: sig, certs: certs}
	if err := sd.SignWithoutAttr(certs[0], adapter, gopkcs7.SignerInfoConfig{}); err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	for i := 1; i < len(certs); i++ {
		sd.AddCertificate(certs[i])
	}
	sd.Detach()

	encoded, err := sd.Finish()
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	// Re-parse to populate caches.
	p7, err := gopkcs7.Parse(encoded)
	if err != nil {
		return nil, &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("self-parse failed after Sign: %v", err),
		}
	}
	e.raw = encoded
	e.certs = certs
	if len(p7.Signers) > 0 {
		e.sigBytes = p7.Signers[0].EncryptedDigest
	}
	return encoded, nil
}

// validateSignRequest enforces the dm-verity profile: non-empty payload,
// no signed-attribute fields, RSA-2048 key only.
func validateSignRequest(req *signature.SignRequest) error {
	if len(req.Payload.Content) == 0 {
		return &signature.InvalidSignRequestError{Msg: "dm-verity PKCS#7 envelope requires a non-empty Payload.Content"}
	}
	if !req.SigningTime.IsZero() {
		return &signature.InvalidSignRequestError{Msg: "dm-verity PKCS#7 envelope does not support SigningTime"}
	}
	if !req.Expiry.IsZero() {
		return &signature.InvalidSignRequestError{Msg: "dm-verity PKCS#7 envelope does not support Expiry"}
	}
	if req.SigningScheme != "" {
		return &signature.InvalidSignRequestError{Msg: "dm-verity PKCS#7 envelope does not support SigningScheme"}
	}
	if req.SigningAgent != "" {
		return &signature.InvalidSignRequestError{Msg: "dm-verity PKCS#7 envelope does not support SigningAgent"}
	}
	if len(req.ExtendedSignedAttributes) > 0 {
		return &signature.InvalidSignRequestError{Msg: "dm-verity PKCS#7 envelope does not support ExtendedSignedAttributes"}
	}

	if req.Signer == nil {
		return &signature.InvalidSignRequestError{Msg: "dm-verity PKCS#7 envelope requires a non-nil Signer"}
	}
	keySpec, err := req.Signer.KeySpec()
	if err != nil {
		return &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// dm-verity profile: RSA-2048 + SHA-256 + RSASSA-PKCS#1 v1.5 only.
	if keySpec.Type != signature.KeyTypeRSA {
		return &signature.UnsupportedSigningKeyError{
			Msg: fmt.Sprintf("dm-verity PKCS#7 envelope requires an RSA key; got %v", keySpec.Type),
		}
	}
	if keySpec.Size != 2048 {
		return &signature.UnsupportedSigningKeyError{
			Msg: fmt.Sprintf("dm-verity PKCS#7 envelope requires RSA-2048; got RSA-%d", keySpec.Size),
		}
	}
	return nil
}

// verifySignerOutput checks that sig is RSASSA-PKCS#1 v1.5 over SHA-256 of
// payload under certs[0]'s public key.
func verifySignerOutput(payload, sig []byte, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return &signature.InvalidSignatureError{Msg: "no certificates returned from signer"}
	}
	if certs[0] == nil {
		return &signature.InvalidSignatureError{Msg: "signer returned a nil leaf certificate"}
	}
	pub, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return &signature.UnsupportedSigningKeyError{
			Msg: fmt.Sprintf("leaf certificate public key is %T, want *rsa.PublicKey", certs[0].PublicKey),
		}
	}
	digest := sha256.Sum256(payload)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("signer did not produce RSASSA-PKCS#1 v1.5 over SHA-256: %v", err),
		}
	}
	return nil
}

// signerAdapter wraps a pre-computed signature so it can be passed to a
// gopkcs7.SignedData (which expects a crypto.Signer). It is single-use:
// Sign must be called at most once.
type signerAdapter struct {
	sig   []byte              // pre-computed signature from actual signer
	certs []*x509.Certificate // certificate chain
	used  bool                // set on first Sign call
}

// Public returns the leaf certificate's public key.
func (a *signerAdapter) Public() crypto.PublicKey {
	if len(a.certs) == 0 {
		panic("pkcs7: signerAdapter constructed with empty cert chain")
	}
	return a.certs[0].PublicKey
}

// Sign returns the pre-computed signature. The digest and opts arguments
// are ignored. Returns an error if called more than once.
func (a *signerAdapter) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if a.used {
		return nil, errors.New("pkcs7: signerAdapter.Sign called more than once")
	}
	a.used = true
	return a.sig, nil
}

// Verify always returns ErrDetachedNotVerifiable for a populated envelope.
func (e *envelope) Verify() (*signature.EnvelopeContent, error) {
	if e.raw == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}
	return nil, ErrDetachedNotVerifiable
}

// Content implements signature.Envelope.
//
// SignerInfo.SignatureAlgorithm is the zero value: signature.Algorithm has
// no constant for RSASSA-PKCS#1 v1.5. Read the certificate chain or the
// CMS digestEncryptionAlgorithm OID instead.
func (e *envelope) Content() (*signature.EnvelopeContent, error) {
	if e.raw == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}
	return &signature.EnvelopeContent{
		SignerInfo: signature.SignerInfo{
			CertificateChain: e.certs,
			Signature:        e.sigBytes,
		},
		// Payload.ContentType identifies the signed payload's media type,
		// not the envelope format. PKCS#7 detached signatures don't carry
		// the payload's content type, so it is unknown after parsing.
		Payload: signature.Payload{},
	}, nil
}

var _ signature.Envelope = (*envelope)(nil)
