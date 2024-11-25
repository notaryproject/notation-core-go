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

package algorithm

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

func TestExtractKeySpec(t *testing.T) {
	type testCase struct {
		name      string
		cert      *x509.Certificate
		expect    KeySpec
		expectErr bool
	}
	// invalid cases
	tests := []testCase{
		{
			name:      "RSA wrong size",
			cert:      testhelper.GetUnsupportedRSACert().Cert,
			expect:    KeySpec{},
			expectErr: true,
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

	// append valid RSA cases
	for _, k := range []int{2048, 3072, 4096} {
		rsaRoot := testhelper.GetRSARootCertificate()
		priv, _ := rsa.GenerateKey(rand.Reader, k)

		certTuple := testhelper.GetRSACertTupleWithPK(
			priv,
			"Test RSA_"+strconv.Itoa(priv.Size()),
			&rsaRoot,
		)
		tests = append(tests, testCase{
			name: "RSA " + strconv.Itoa(k),
			cert: certTuple.Cert,
			expect: KeySpec{
				Type: KeyTypeRSA,
				Size: k,
			},
			expectErr: false,
		})
	}

	// append valid EDCSA cases
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		ecdsaRoot := testhelper.GetECRootCertificate()
		priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
		bitSize := priv.Params().BitSize

		certTuple := testhelper.GetECDSACertTupleWithPK(
			priv,
			"Test EC_"+strconv.Itoa(bitSize),
			&ecdsaRoot,
		)
		tests = append(tests, testCase{
			name: "EC " + strconv.Itoa(bitSize),
			cert: certTuple.Cert,
			expect: KeySpec{
				Type: KeyTypeEC,
				Size: bitSize,
			},
			expectErr: false,
		})
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
