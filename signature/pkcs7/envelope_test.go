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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
)

const testPayload = "test dm-verity root hash payload"

// newRSATestSigner creates an RSA-2048 test signer using testhelper certs.
func newRSATestSigner() *testPrimitiveSigner {
	tuple := testhelper.GetRSACertTuple(2048)
	rootCert := testhelper.GetRSARootCertificate().Cert
	return &testPrimitiveSigner{
		key:     tuple.PrivateKey,
		certs:   []*x509.Certificate{tuple.Cert, rootCert},
		keySpec: signature.KeySpec{Type: signature.KeyTypeRSA, Size: 2048},
	}
}

// testPrimitiveSigner implements signature.Signer for testing.
type testPrimitiveSigner struct {
	key     crypto.PrivateKey
	certs   []*x509.Certificate
	keySpec signature.KeySpec
}

func (s *testPrimitiveSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	h := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key.(*rsa.PrivateKey), crypto.SHA256, h[:])
	if err != nil {
		return nil, nil, err
	}
	return sig, s.certs, nil
}

func (s *testPrimitiveSigner) KeySpec() (signature.KeySpec, error) {
	return s.keySpec, nil
}

// TestSignParseVerifyRoundTrip tests the full Sign → Parse → Verify → Content flow.
func TestSignParseVerifyRoundTrip(t *testing.T) {
	env := NewEnvelope()
	signer := newRSATestSigner()

	req := &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: MediaTypeEnvelope,
			Content:     []byte(testPayload),
		},
		Signer: signer,
	}

	encoded, err := env.Sign(req)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("Sign() returned empty bytes")
	}

	// Parse
	parsed, err := ParseEnvelope(encoded)
	if err != nil {
		t.Fatalf("ParseEnvelope() error: %v", err)
	}

	// Verify
	verifyContent, err := parsed.Verify()
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if len(verifyContent.SignerInfo.Signature) == 0 {
		t.Fatal("Verify() returned empty signature")
	}

	// Content
	content, err := parsed.Content()
	if err != nil {
		t.Fatalf("Content() error: %v", err)
	}
	if len(content.SignerInfo.CertificateChain) == 0 {
		t.Fatal("Content() returned no certificates")
	}
	if content.Payload.ContentType != MediaTypeEnvelope {
		t.Fatalf("Content().Payload.ContentType = %q, want %q",
			content.Payload.ContentType, MediaTypeEnvelope)
	}
}

// TestParseEnvelopeError tests that invalid input is rejected.
func TestParseEnvelopeError(t *testing.T) {
	_, err := ParseEnvelope([]byte("invalid"))
	if err == nil {
		t.Fatal("ParseEnvelope(invalid) expected error, got nil")
	}
	var target *signature.InvalidSignatureError
	if !errors.As(err, &target) {
		t.Fatalf("expected InvalidSignatureError, got %T", err)
	}
}

// TestSignError tests that Sign fails with a broken signer.
func TestSignError(t *testing.T) {
	env := NewEnvelope()
	req := &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: MediaTypeEnvelope,
			Content:     []byte(testPayload),
		},
		Signer: &failingSigner{},
	}
	_, err := env.Sign(req)
	if err == nil {
		t.Fatal("Sign() with failing signer expected error, got nil")
	}
}

// TestVerifyEmptyEnvelope tests that Verify fails on an unsigned envelope.
func TestVerifyEmptyEnvelope(t *testing.T) {
	env := NewEnvelope()
	_, err := env.Verify()
	if err == nil {
		t.Fatal("Verify() on empty envelope expected error, got nil")
	}
}

// TestEnvelopeRegistration verifies the media type was registered via init().
func TestEnvelopeRegistration(t *testing.T) {
	env, err := signature.NewEnvelope(MediaTypeEnvelope)
	if err != nil {
		t.Fatalf("NewEnvelope(%q) error: %v", MediaTypeEnvelope, err)
	}
	if env == nil {
		t.Fatal("NewEnvelope() returned nil for registered media type")
	}
}

// failingSigner is a test signer whose Sign() always fails.
type failingSigner struct{}

func (s *failingSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	return nil, nil, errors.New("signing failed")
}

func (s *failingSigner) KeySpec() (signature.KeySpec, error) {
	return signature.KeySpec{Type: signature.KeyTypeRSA, Size: 2048}, nil
}
