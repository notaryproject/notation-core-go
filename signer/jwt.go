package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

// signJWT signs the given payload and headers using the given signing method and signature provider
func signJWT(payload, headers map[string]interface{}, method jwt.SigningMethod, sigPro SignatureProvider) (string, error) {
	var claims jwt.MapClaims = payload
	token := &jwt.Token{
		Header: headers,
		Claims: claims,
	}

	token.Method = signingMethodForSign{algo: method.Alg(), sigProvider: sigPro}

	// We are using custom signing method called `signingMethodForSign` which already has signature provider
	// thus we don't need to pass signing key as input.
	return token.SignedString(nil)
}

// verifyJWT verifies the JWT token against the specified verification key
func verifyJWT(tokenString string, key crypto.PublicKey) error {
	signingMethod, err := getSigningMethod(key)
	if err != nil {
		return err
	}

	// parse and verify token
	parser := &jwt.Parser{
		ValidMethods:         []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"},
		UseJSONNumber:        true,
		SkipClaimsValidation: true,
	}

	if _, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != signingMethod.Alg() {
			return nil, MalformedSignatureError{msg: fmt.Sprintf("unexpected signing method: %v: require %v", t.Method.Alg(), signingMethod.Alg())}
		}

		// override default signing method with key-specific method
		t.Method = signingMethod
		return key, nil
	}); err != nil {
		return SignatureIntegrityError{err: err}
	}
	return nil
}

// signingMethodForSign is only used during signature generation operation. It's required by JWT library we are using
type signingMethodForSign struct {
	algo        string
	sigProvider SignatureProvider
}

func (s signingMethodForSign) Verify(_, _ string, _ interface{}) error {
	return UnsupportedOperationError{}
}

func (s signingMethodForSign) Sign(signingString string, _ interface{}) (string, error) {
	seg, err := s.sigProvider.Sign([]byte(signingString))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(seg), nil
}

func (s signingMethodForSign) Alg() string {
	return s.algo
}

// getSigningMethod picks up a recommended algorithm for given public keys.
func getSigningMethod(key crypto.PublicKey) (jwt.SigningMethod, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return jwt.SigningMethodPS256, nil
		case 384:
			return jwt.SigningMethodPS384, nil
		case 512:
			return jwt.SigningMethodPS512, nil
		default:
			return nil, UnsupportedSigningKeyError{keyType: "rsa"}
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case jwt.SigningMethodES256.CurveBits:
			return jwt.SigningMethodES256, nil
		case jwt.SigningMethodES384.CurveBits:
			return jwt.SigningMethodES384, nil
		case jwt.SigningMethodES512.CurveBits:
			return jwt.SigningMethodES512, nil
		default:
			return nil, UnsupportedSigningKeyError{keyType: "ecdsa"}
		}
	}
	return nil, UnsupportedSigningKeyError{}
}
