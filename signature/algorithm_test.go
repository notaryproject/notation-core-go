package signature

import (
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
