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
	"time"

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

// newSignRequest builds a SignRequest backed by an RSA-2048 test signer.
func newSignRequest() *signature.SignRequest {
	return &signature.SignRequest{
		Payload: signature.Payload{ContentType: MediaTypeEnvelope, Content: []byte(testPayload)},
		Signer:  newRSATestSigner(),
	}
}

// TestSignParseVerifyRoundTrip exercises Sign → Parse → Verify → Content.
func TestSignParseVerifyRoundTrip(t *testing.T) {
	encoded, err := NewEnvelope().Sign(newSignRequest())
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("Sign() returned empty bytes")
	}

	parsed, err := ParseEnvelope(encoded)
	if err != nil {
		t.Fatalf("ParseEnvelope() error: %v", err)
	}

	if _, err := parsed.Verify(); !errors.Is(err, ErrDetachedNotVerifiable) {
		t.Fatalf("Verify() = %v, want ErrDetachedNotVerifiable", err)
	}

	content, err := parsed.Content()
	if err != nil {
		t.Fatalf("Content() error: %v", err)
	}
	if len(content.SignerInfo.CertificateChain) == 0 {
		t.Fatal("Content() returned no certificates")
	}
	if content.Payload.ContentType != MediaTypeEnvelope {
		t.Fatalf("ContentType = %q, want %q", content.Payload.ContentType, MediaTypeEnvelope)
	}
}

func TestParseEnvelopeError(t *testing.T) {
	_, err := ParseEnvelope([]byte("invalid"))
	var target *signature.InvalidSignatureError
	if !errors.As(err, &target) {
		t.Fatalf("want InvalidSignatureError, got %T: %v", err, err)
	}
}

func TestSignError(t *testing.T) {
	req := newSignRequest()
	req.Signer = &stubSigner{
		keySpec: signature.KeySpec{Type: signature.KeyTypeRSA, Size: 2048},
		signErr: errors.New("signing failed"),
	}
	if _, err := NewEnvelope().Sign(req); err == nil {
		t.Fatal("Sign() with failing signer expected error, got nil")
	}
}

func TestVerifyEmptyEnvelope(t *testing.T) {
	if _, err := NewEnvelope().Verify(); err == nil {
		t.Fatal("Verify() on empty envelope expected error, got nil")
	}
}

func TestEnvelopeRegistration(t *testing.T) {
	env, err := signature.NewEnvelope(MediaTypeEnvelope)
	if err != nil {
		t.Fatalf("NewEnvelope(%q) error: %v", MediaTypeEnvelope, err)
	}
	if env == nil {
		t.Fatal("NewEnvelope() returned nil for registered media type")
	}
}

// TestSignRejectsNonRSA2048 verifies that Sign refuses key specs outside
// the dm-verity profile (RSA-2048 only).
func TestSignRejectsNonRSA2048(t *testing.T) {
	cases := []struct {
		name    string
		keySpec signature.KeySpec
	}{
		{"ecdsa-p256", signature.KeySpec{Type: signature.KeyTypeEC, Size: 256}},
		{"rsa-3072", signature.KeySpec{Type: signature.KeyTypeRSA, Size: 3072}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEnvelope().Sign(&signature.SignRequest{
				Payload: signature.Payload{ContentType: MediaTypeEnvelope, Content: []byte(testPayload)},
				Signer:  &stubSigner{keySpec: tc.keySpec},
			})
			var want *signature.UnsupportedSigningKeyError
			if !errors.As(err, &want) {
				t.Fatalf("want UnsupportedSigningKeyError, got %T: %v", err, err)
			}
		})
	}
}

// stubSigner reports a fixed KeySpec and returns signErr from Sign().
type stubSigner struct {
	keySpec signature.KeySpec
	signErr error
}

func (s *stubSigner) Sign([]byte) ([]byte, []*x509.Certificate, error) {
	if s.signErr == nil {
		return nil, nil, errors.New("stubSigner.Sign: no signErr configured")
	}
	return nil, nil, s.signErr
}
func (s *stubSigner) KeySpec() (signature.KeySpec, error) { return s.keySpec, nil }

// TestSignRejectsSignedAttributeFields verifies that signed-attribute
// fields on the SignRequest are rejected.
func TestSignRejectsSignedAttributeFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*signature.SignRequest)
	}{
		{"SigningTime", func(r *signature.SignRequest) { r.SigningTime = time.Now() }},
		{"Expiry", func(r *signature.SignRequest) { r.Expiry = time.Now().Add(time.Hour) }},
		{"SigningScheme", func(r *signature.SignRequest) { r.SigningScheme = signature.SigningSchemeX509 }},
		{"SigningAgent", func(r *signature.SignRequest) { r.SigningAgent = "notation/0.0" }},
		{"ExtendedSignedAttributes", func(r *signature.SignRequest) {
			r.ExtendedSignedAttributes = []signature.Attribute{{Key: "k", Value: "v"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newSignRequest()
			tc.mutate(req)
			_, err := NewEnvelope().Sign(req)
			var want *signature.InvalidSignRequestError
			if !errors.As(err, &want) {
				t.Fatalf("want InvalidSignRequestError, got %T: %v", err, err)
			}
		})
	}
}

// TestSignRejectsNilSigner verifies that a SignRequest with a nil Signer
// returns a typed error.
func TestSignRejectsNilSigner(t *testing.T) {
	_, err := NewEnvelope().Sign(&signature.SignRequest{
		Payload: signature.Payload{ContentType: MediaTypeEnvelope, Content: []byte(testPayload)},
	})
	var want *signature.InvalidSignRequestError
	if !errors.As(err, &want) {
		t.Fatalf("want InvalidSignRequestError, got %T: %v", err, err)
	}
}

// TestSignRejectsBadSignerOutput verifies that a signer returning bytes
// other than RSASSA-PKCS#1 v1.5 over SHA-256 is rejected.
func TestSignRejectsBadSignerOutput(t *testing.T) {
	base := newRSATestSigner()
	cases := []struct {
		name string
		sign func(payload []byte) ([]byte, error)
	}{
		{"pss-instead-of-pkcs1v15", func(payload []byte) ([]byte, error) {
			h := sha256.Sum256(payload)
			return rsa.SignPSS(rand.Reader, base.key.(*rsa.PrivateKey), crypto.SHA256, h[:], nil)
		}},
		{"random-bytes", func([]byte) ([]byte, error) {
			b := make([]byte, 256) // RSA-2048 signature length
			_, err := rand.Read(b)
			return b, err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEnvelope().Sign(&signature.SignRequest{
				Payload: signature.Payload{ContentType: MediaTypeEnvelope, Content: []byte(testPayload)},
				Signer:  &customSignSigner{certs: base.certs, keySpec: base.keySpec, sign: tc.sign},
			})
			var want *signature.InvalidSignatureError
			if !errors.As(err, &want) {
				t.Fatalf("want InvalidSignatureError, got %T: %v", err, err)
			}
		})
	}
}

// customSignSigner delegates Sign() to a caller-supplied function.
type customSignSigner struct {
	certs   []*x509.Certificate
	keySpec signature.KeySpec
	sign    func(payload []byte) ([]byte, error)
}

func (s *customSignSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	sig, err := s.sign(payload)
	if err != nil {
		return nil, nil, err
	}
	return sig, s.certs, nil
}
func (s *customSignSigner) KeySpec() (signature.KeySpec, error) { return s.keySpec, nil }
