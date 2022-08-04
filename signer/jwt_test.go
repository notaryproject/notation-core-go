package signer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestVerifyJWTError(t *testing.T) {
	t.Run("with_unsupported_signingKey", func(t *testing.T) {
		edKey, _, _ := ed25519.GenerateKey(rand.Reader)
		err := verifyJWT("", &edKey)
		if !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("verifyJWT(). Expected UnsupportedSigningKeyError but but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with_signature_containing_unsupported_alg", func(t *testing.T) {
		jwtSig := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		err := verifyJWT(jwtSig, &rsaKey.PublicKey)
		if !(err != nil && errors.As(err, new(SignatureIntegrityError))) {
			t.Errorf("verifyJWT(). Expected UnsupportedSigningKeyError but but found %q %s", reflect.TypeOf(err), err)
		}
	})
}

func TestGetSigningMethod(t *testing.T) {
	for k, v := range map[int]*jwt.SigningMethodRSAPSS{
		2048: jwt.SigningMethodPS256,
		3072: jwt.SigningMethodPS384,
		4096: jwt.SigningMethodPS512} {
		key, _ := rsa.GenerateKey(rand.Reader, k)
		m, err := getSigningMethod(&key.PublicKey)
		if m != v || err != nil {
			t.Fatalf("GenerateKey(). error = %v", err)
		}
	}

	for k, v := range map[elliptic.Curve]*jwt.SigningMethodECDSA{
		elliptic.P256(): jwt.SigningMethodES256,
		elliptic.P384(): jwt.SigningMethodES384,
		elliptic.P521(): jwt.SigningMethodES512} {
		key, _ := ecdsa.GenerateKey(k, rand.Reader)
		m, err := getSigningMethod(&key.PublicKey)
		if m != v || err != nil {
			t.Fatalf("GenerateKey(). error = %v", err)
		}
	}
}

func TestGetSigningMethodError(t *testing.T) {
	t.Run("with_unsupported_rsa_Key", func(t *testing.T) {
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 6114)
		_, err := getSigningMethod(&rsaKey.PublicKey)
		if !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("GenerateKey(). Expected UnsupportedSigningKeyError but but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with_unsupported_ec_Key", func(t *testing.T) {
		esKey, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		_, err := getSigningMethod(&esKey.PublicKey)
		if !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("GenerateKey(). Expected UnsupportedSigningKeyError but but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with_unsupported_ed_Key", func(t *testing.T) {
		edKey, _, _ := ed25519.GenerateKey(rand.Reader)
		_, err := getSigningMethod(&edKey)
		if !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("GenerateKey(). Expected UnsupportedSigningKeyError but but found %q", reflect.TypeOf(err))
		}
	})
}
