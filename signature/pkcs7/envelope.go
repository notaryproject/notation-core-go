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

// Package pkcs7 provides PKCS#7/CMS signature envelope for dm-verity signing.
// Supports both local keys and remote signers (Azure Key Vault, plugins) via
// the signerAdapter pattern.
package pkcs7

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/notaryproject/notation-core-go/signature"
	gopkcs7 "go.mozilla.org/pkcs7"
)

// MediaTypeEnvelope is the PKCS#7 signature envelope media type.
const MediaTypeEnvelope = "application/pkcs7-signature"

func init() {
	if err := signature.RegisterEnvelopeType(MediaTypeEnvelope, NewEnvelope, ParseEnvelope); err != nil {
		panic(err)
	}
}

type envelope struct {
	raw      []byte
	p7       *gopkcs7.PKCS7
	certs    []*x509.Certificate
	sigBytes []byte
}

// NewEnvelope creates a new PKCS#7 envelope.
// Note: Unlike JWS/COSE, PKCS#7 for dm-verity does NOT use base.Envelope wrapper
// because dm-verity signatures must not have signing-time (kernel requirement).
func NewEnvelope() signature.Envelope {
	return &envelope{}
}

// ParseEnvelope parses PKCS#7 DER bytes into an envelope.
func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	p7, err := gopkcs7.Parse(envelopeBytes)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	var sigBytes []byte
	if len(p7.Signers) > 0 {
		sigBytes = p7.Signers[0].EncryptedDigest
	}

	return &envelope{
		raw:      envelopeBytes,
		p7:       p7,
		certs:    p7.Certificates,
		sigBytes: sigBytes,
	}, nil
}

// Sign implements signature.Envelope interface.
// Uses signerAdapter pattern to support both local and remote signers (AKV, plugins).
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	// Get key spec to determine algorithm
	keySpec, err := req.Signer.KeySpec()
	if err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// Sign the content using the underlying signer (works with AKV, local keys, etc.)
	sig, certs, err := req.Signer.Sign(req.Payload.Content)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: fmt.Sprintf("signing failed: %v", err)}
	}

	if len(certs) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "no certificates returned from signer"}
	}

	// Create a crypto.Signer adapter that returns our pre-computed signature
	adapter := &signerAdapter{
		sig:   sig,
		certs: certs,
	}

	// Build PKCS#7 SignedData using mozilla library
	sd, err := gopkcs7.NewSignedData(req.Payload.Content)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	// Set digest algorithm to SHA-256 (kernel dm-verity requirement)
	sd.SetDigestAlgorithm(gopkcs7.OIDDigestAlgorithmSHA256)

	// Set encryption algorithm based on key type
	encryptionOID, err := getEncryptionOID(keySpec)
	if err != nil {
		return nil, &signature.UnsupportedSigningKeyError{Msg: err.Error()}
	}
	sd.SetEncryptionAlgorithm(encryptionOID)

	// Sign without authenticated attributes (kernel dm-verity requirement)
	if err := sd.SignWithoutAttr(certs[0], adapter, gopkcs7.SignerInfoConfig{}); err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	// Add intermediate/CA certificates to the chain
	for i := 1; i < len(certs); i++ {
		sd.AddCertificate(certs[i])
	}

	// Create detached signature (content not embedded)
	sd.Detach()

	encoded, err := sd.Finish()
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	// Parse the result to populate envelope fields
	p7, _ := gopkcs7.Parse(encoded)
	e.raw = encoded
	e.p7 = p7
	e.certs = certs
	if p7 != nil && len(p7.Signers) > 0 {
		e.sigBytes = p7.Signers[0].EncryptedDigest
	}

	return encoded, nil
}

// getEncryptionOID returns the encryption algorithm OID for the key spec.
func getEncryptionOID(keySpec signature.KeySpec) (asn1.ObjectIdentifier, error) {
	switch keySpec.Type {
	case signature.KeyTypeRSA:
		return gopkcs7.OIDEncryptionAlgorithmRSA, nil
	case signature.KeyTypeEC:
		switch keySpec.Size {
		case 256:
			return gopkcs7.OIDEncryptionAlgorithmECDSAP256, nil
		case 384:
			return gopkcs7.OIDEncryptionAlgorithmECDSAP384, nil
		case 521:
			return gopkcs7.OIDEncryptionAlgorithmECDSAP521, nil
		default:
			return nil, fmt.Errorf("unsupported EC key size: %d", keySpec.Size)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keySpec.Type)
	}
}

// signerAdapter wraps a pre-computed signature to satisfy crypto.Signer interface.
// This enables remote signers (Azure Key Vault, plugins) to work with the
// mozilla pkcs7 library which expects crypto.Signer.
type signerAdapter struct {
	sig   []byte              // pre-computed signature from actual signer
	certs []*x509.Certificate // certificate chain
}

// Public returns the public key from the leaf certificate.
func (a *signerAdapter) Public() crypto.PublicKey {
	if len(a.certs) > 0 {
		return a.certs[0].PublicKey
	}
	return nil
}

// Sign returns the pre-computed signature.
// The digest parameter is ignored since signing already happened via req.Signer.Sign().
func (a *signerAdapter) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return a.sig, nil
}

// Verify implements signature.Envelope interface.
func (e *envelope) Verify() (*signature.EnvelopeContent, error) {
	if e.raw == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}
	// For detached signatures, the kernel does dm-verity verification
	return e.Content()
}

// Content implements signature.Envelope interface.
func (e *envelope) Content() (*signature.EnvelopeContent, error) {
	if e.raw == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}

	alg, err := extractAlgorithm(e.certs)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	return &signature.EnvelopeContent{
		SignerInfo: signature.SignerInfo{
			SignatureAlgorithm: alg,
			CertificateChain:   e.certs,
			Signature:          e.sigBytes,
		},
		Payload: signature.Payload{
			ContentType: MediaTypeEnvelope,
		},
	}, nil
}

// extractAlgorithm derives the signature algorithm from the leaf certificate.
func extractAlgorithm(certs []*x509.Certificate) (signature.Algorithm, error) {
	if len(certs) == 0 {
		return 0, fmt.Errorf("no certificates available to determine algorithm")
	}
	keySpec, err := signature.ExtractKeySpec(certs[0])
	if err != nil {
		return 0, err
	}
	return keySpec.SignatureAlgorithm(), nil
}
