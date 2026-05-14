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

package pkcs7

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	gopkcs7 "go.mozilla.org/pkcs7"

	"github.com/notaryproject/notation-core-go/signature"
)

// TestConformance asserts that Sign() produces a PKCS#7 SignedData that meets
// the kernel dm-verity profile: RSASSA-PKCS#1 v1.5 over SHA-256, no signed
// attributes, detached content, single signer.
func TestConformance(t *testing.T) {
	signer := newRSATestSigner()
	encoded, err := NewEnvelope().Sign(&signature.SignRequest{
		Payload: signature.Payload{ContentType: MediaTypeEnvelope, Content: []byte(testPayload)},
		Signer:  signer,
	})
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	p7, err := gopkcs7.Parse(encoded)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if got, want := len(p7.Signers), 1; got != want {
		t.Fatalf("Signers = %d, want %d", got, want)
	}

	// Cert chain must be leaf + root. dm-verity has no intermediates.
	if got, want := len(p7.Certificates), 2; got != want {
		t.Fatalf("Certificates = %d, want %d (leaf + root)", got, want)
	}
	if !p7.Certificates[0].Equal(signer.certs[0]) {
		t.Errorf("Certificates[0] is not the leaf certificate")
	}
	if !p7.Certificates[1].Equal(signer.certs[1]) {
		t.Errorf("Certificates[1] is not the root certificate")
	}

	si := p7.Signers[0]
	if !si.DigestAlgorithm.Algorithm.Equal(gopkcs7.OIDDigestAlgorithmSHA256) {
		t.Errorf("DigestAlgorithm = %v, want SHA-256", si.DigestAlgorithm.Algorithm)
	}
	if !si.DigestEncryptionAlgorithm.Algorithm.Equal(gopkcs7.OIDEncryptionAlgorithmRSA) {
		t.Errorf("DigestEncryptionAlgorithm = %v, want rsaEncryption", si.DigestEncryptionAlgorithm.Algorithm)
	}
	if len(si.AuthenticatedAttributes) != 0 {
		t.Errorf("AuthenticatedAttributes len = %d, want 0", len(si.AuthenticatedAttributes))
	}
	if len(p7.Content) != 0 {
		t.Errorf("Content len = %d, want 0 (must be detached)", len(p7.Content))
	}

	// Independently verify the bytes are RSASSA-PKCS#1 v1.5 over SHA-256
	// of the payload.
	digest := sha256.Sum256([]byte(testPayload))
	pub, ok := signer.certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("leaf public key is %T, want *rsa.PublicKey", signer.certs[0].PublicKey)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], si.EncryptedDigest); err != nil {
		t.Fatalf("rsa.VerifyPKCS1v15 over SHA-256(payload) failed: %v", err)
	}
}
