package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"testing"

	"github.com/notaryproject/notation-core-go/internal/crypto/hashutil"
	"github.com/notaryproject/notation-core-go/testhelper"
)

// Tests local signature provider for various size of RSA and EC certificates
func TestLocalSignatureProvider(t *testing.T) {
	payload := []byte("SignMe!")
	rsaRoot := testhelper.GetRSARootCertificate()
	for k, v := range map[int]crypto.Hash{2048: crypto.SHA256, 3072: crypto.SHA384, 4096: crypto.SHA512} {
		pk, _ := rsa.GenerateKey(rand.Reader, k)
		certTuple := testhelper.GetRSACertTupleWithPK(pk, "TestDeriveSignatureAlgorithm_"+strconv.Itoa(pk.Size()), &rsaRoot)
		t.Run(fmt.Sprintf("for RSA certificates of size %d", pk.Size()), func(t *testing.T) {
			lsp, err := NewLocalSignatureProvider([]*x509.Certificate{certTuple.Cert, rsaRoot.Cert}, pk)
			if err != nil {
				t.Errorf("NewLocalSignatureProvider(). Error: %s", err)
			}

			sig, certs, err := lsp.Sign(payload)
			if err != nil {
				t.Errorf("Sign(). Error: %s", err)
			}

			if !(certs[0] == certTuple.Cert && certs[1] == rsaRoot.Cert) {
				t.Error("Signing certificates Mismatch")
			}

			hs, _ := hashutil.ComputeHash(v, payload)
			err = rsa.VerifyPSS(&pk.PublicKey, v, hs, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Errorf("Invalid signature generated. Error: %s", err)
			}
		})
	}

	ecRoot := testhelper.GetECRootCertificate()
	for k, v := range map[elliptic.Curve]crypto.Hash{elliptic.P256(): crypto.SHA256, elliptic.P384(): crypto.SHA384, elliptic.P521(): crypto.SHA512} {
		pk, _ := ecdsa.GenerateKey(k, rand.Reader)
		certTuple := testhelper.GetECDSACertTupleWithPK(pk, "TestDeriveSignatureAlgorithm_"+strconv.Itoa(pk.Params().BitSize), &ecRoot)

		t.Run(fmt.Sprintf("for EC certificates of size %d", pk.Params().BitSize), func(t *testing.T) {
			lsp, err := NewLocalSignatureProvider([]*x509.Certificate{certTuple.Cert, ecRoot.Cert}, pk)
			if err != nil {
				t.Errorf("NewLocalSignatureProvider(). Error: %s", err)
			}

			sig, certs, err := lsp.Sign(payload)
			if err != nil {
				t.Errorf("Sign(). Error: %s", err)
			}

			if !(certs[0] == certTuple.Cert && certs[1] == ecRoot.Cert) {
				t.Error("Signing certificates Mismatch")
			}

			hs, _ := hashutil.ComputeHash(v, payload)
			keysize := int(math.Ceil(float64(pk.Curve.Params().BitSize) / float64(8)))
			r := big.NewInt(0).SetBytes(sig[:keysize])
			s := big.NewInt(0).SetBytes(sig[keysize:])
			ok := ecdsa.Verify(&pk.PublicKey, hs, r, s)
			if !ok {
				t.Errorf("Invalid signature generated. Error: %s", err)
			}
		})
	}
}

// Tests various scenarios around generating a signature envelope
func TestLocalSignatureProviderError(t *testing.T) {
	t.Run("for unsupported RSA certificate", func(t *testing.T) {
		k := 1024
		rsaRoot := testhelper.GetRSARootCertificate()
		pk, _ := rsa.GenerateKey(rand.Reader, k)
		certTuple := testhelper.GetRSACertTupleWithPK(pk, "TestDeriveSignatureAlgorithm_"+strconv.Itoa(pk.Size()), &rsaRoot)

		_, err := NewLocalSignatureProvider([]*x509.Certificate{certTuple.Cert, rsaRoot.Cert}, pk)
		if !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("Expected UnsupportedSigningKeyError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("for unsupported EC certificate", func(t *testing.T) {
		ecRoot := testhelper.GetECRootCertificate()
		k := elliptic.P224()
		pk, _ := ecdsa.GenerateKey(k, rand.Reader)
		certTuple := testhelper.GetECDSACertTupleWithPK(pk, "TestDeriveSignatureAlgorithm_"+strconv.Itoa(pk.Params().BitSize), &ecRoot)

		_, err := NewLocalSignatureProvider([]*x509.Certificate{certTuple.Cert, ecRoot.Cert}, pk)
		if !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("Expected UnsupportedSigningKeyError but found %q", reflect.TypeOf(err))
		}
	})
}

func TestDeriveSignatureAlgorithm(t *testing.T) {
	rsaRoot := testhelper.GetRSARootCertificate()
	for _, v := range []int{2048, 3072, 4096} {
		pk, _ := rsa.GenerateKey(rand.Reader, v)
		certTuple := testhelper.GetRSACertTupleWithPK(pk, "TestDeriveSignatureAlgorithm_"+strconv.Itoa(pk.Size()), &rsaRoot)
		t.Run(fmt.Sprintf("for RSA certificates of size %d", pk.Size()), func(t *testing.T) {
			_, err := getSignatureAlgorithm(certTuple.Cert)
			if err != nil {
				t.Errorf("getSignatureAlgorithm(). Error: %s", err)
			}
		})
	}

	ecRoot := testhelper.GetECRootCertificate()
	for _, v := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		pk, _ := ecdsa.GenerateKey(v, rand.Reader)
		certTuple := testhelper.GetECDSACertTupleWithPK(pk, "TestDeriveSignatureAlgorithm_"+strconv.Itoa(pk.Params().BitSize), &ecRoot)
		t.Run(fmt.Sprintf("for EC certificates of size %d", pk.Params().BitSize), func(t *testing.T) {
			_, err := getSignatureAlgorithm(certTuple.Cert)
			if err != nil {
				t.Errorf("getSignatureAlgorithm(). Error: %s", err)
			}
		})
	}
}

func TestDeriveSignatureAlgorithmError(t *testing.T) {
	t.Run("for unsupported RSA certificate", func(t *testing.T) {
		rsaRoot := testhelper.GetRSARootCertificate()
		pk, _ := rsa.GenerateKey(rand.Reader, 1024)
		certTuple := testhelper.GetRSACertTupleWithPK(pk, "TestDeriveSignatureAlgorithm_"+strconv.Itoa(pk.Size()), &rsaRoot)

		_, err := getSignatureAlgorithm(certTuple.Cert)
		if !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("Expected UnsupportedSigningKeyError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("for unsupported EC certificate", func(t *testing.T) {
		ecRoot := testhelper.GetECRootCertificate()
		pk, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		certTuple := testhelper.GetECDSACertTupleWithPK(pk, "TestDeriveSignatureAlgorithm_"+strconv.Itoa(pk.Params().BitSize), &ecRoot)

		_, err := getSignatureAlgorithm(certTuple.Cert)
		if !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("Expected UnsupportedSigningKeyError but found %q", reflect.TypeOf(err))
		}
	})
}
