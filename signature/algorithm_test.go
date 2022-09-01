package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"reflect"
	"strconv"
	"testing"

	"github.com/notaryproject/notation-core-go/testhelper"
)

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
