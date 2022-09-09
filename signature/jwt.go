package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

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
			return nil, UnsupportedSigningKeyError{keyType: "rsa", keyLength: key.Size()}
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
			return nil, UnsupportedSigningKeyError{keyType: "ecdsa", keyLength: key.Curve.Params().BitSize}
		}
	}
	return nil, UnsupportedSigningKeyError{}
}
