package signature

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestHash(t *testing.T) {
	tests := []struct {
		name   string
		alg    Algorithm
		expect crypto.Hash
	}{
		{
			name:   "PS256",
			alg:    AlgorithmPS256,
			expect: crypto.SHA256,
		},
		{
			name:   "ES256",
			alg:    AlgorithmES256,
			expect: crypto.SHA256,
		},
		{
			name:   "PS384",
			alg:    AlgorithmPS384,
			expect: crypto.SHA384,
		},
		{
			name:   "ES384",
			alg:    AlgorithmES384,
			expect: crypto.SHA384,
		},
		{
			name:   "PS512",
			alg:    AlgorithmPS512,
			expect: crypto.SHA512,
		},
		{
			name:   "ES512",
			alg:    AlgorithmES512,
			expect: crypto.SHA512,
		},
		{
			name:   "UnsupportedAlgorithm",
			alg:    0,
			expect: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := tt.alg.Hash()
			if hash != tt.expect {
				t.Fatalf("Expected %v, got %v", tt.expect, hash)
			}
		})
	}
}

func TestExtractKeySpec(t *testing.T) {
	tests := []struct {
		name      string
		cert      *x509.Certificate
		expect    KeySpec
		expectErr bool
	}{
		{
			name: "RSA 3072",
			cert: testhelper.GetRSALeafCertificate().Cert,
			expect: KeySpec{
				Type: KeyTypeRSA,
				Size: 3072,
			},
			expectErr: false,
		},
		{
			name:      "RSA wrong size",
			cert:      testhelper.GetUnsupportedRSACert().Cert,
			expect:    KeySpec{},
			expectErr: true,
		},
		{
			name: "ECDSA 384",
			cert: testhelper.GetECLeafCertificate().Cert,
			expect: KeySpec{
				Type: KeyTypeEC,
				Size: 384,
			},
			expectErr: false,
		},
		{
			name:      "ECDSA wrong size",
			cert:      testhelper.GetUnsupportedECCert().Cert,
			expect:    KeySpec{},
			expectErr: true,
		},
		{
			name: "Unsupported type",
			cert: &x509.Certificate{
				PublicKey: ed25519.PublicKey{},
			},
			expect:    KeySpec{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keySpec, err := ExtractKeySpec(tt.cert)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(keySpec, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, keySpec)
			}
		})
	}
}

func TestSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		keySpec KeySpec
		expect  Algorithm
	}{
		{
			name: "EC 256",
			keySpec: KeySpec{
				Type: KeyTypeEC,
				Size: 256,
			},
			expect: AlgorithmES256,
		},
		{
			name: "EC 384",
			keySpec: KeySpec{
				Type: KeyTypeEC,
				Size: 384,
			},
			expect: AlgorithmES384,
		},
		{
			name: "EC 521",
			keySpec: KeySpec{
				Type: KeyTypeEC,
				Size: 521,
			},
			expect: AlgorithmES512,
		},
		{
			name: "RSA 2048",
			keySpec: KeySpec{
				Type: KeyTypeRSA,
				Size: 2048,
			},
			expect: AlgorithmPS256,
		},
		{
			name: "RSA 3072",
			keySpec: KeySpec{
				Type: KeyTypeRSA,
				Size: 3072,
			},
			expect: AlgorithmPS384,
		},
		{
			name: "RSA 4096",
			keySpec: KeySpec{
				Type: KeyTypeRSA,
				Size: 4096,
			},
			expect: AlgorithmPS512,
		},
		{
			name: "Unsupported key spec",
			keySpec: KeySpec{
				Type: 0,
				Size: 0,
			},
			expect: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg := tt.keySpec.SignatureAlgorithm()
			if alg != tt.expect {
				t.Errorf("unexpected signature algorithm: %v, expect: %v", alg, tt.expect)
			}
		})
	}
}
