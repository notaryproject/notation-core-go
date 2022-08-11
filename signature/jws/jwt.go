package jws

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signature"
)

// remoteSigningMethod wraps the remote signer to be a jwt.SigningMethod
type remoteSigningMethod struct {
	signer signature.Signer
}

func newRemoteSigningMethod(signer signature.Signer) (jwt.SigningMethod, error) {
	return &remoteSigningMethod{signer: signer}, nil
}

// Verify doesn't need to be implemented.
func (s *remoteSigningMethod) Verify(signingString, signature string, key interface{}) error {
	panic("not implemented")
}

// Sign hashes the signingString and call the remote signer to sign the digest.
func (s *remoteSigningMethod) Sign(signingString string, key interface{}) (string, error) {
	keySpec, err := s.signer.KeySpec()
	if err != nil {
		return "", err
	}

	// get hasher
	hasher := keySpec.SignatureAlgorithm().Hash()
	if !hasher.Available() {
		return "", &signature.SignatureAlgoNotSupportedError{Alg: hasher.String()}
	}

	// calculate hash
	h := hasher.New()
	h.Write([]byte(signingString))
	hash := h.Sum(nil)

	// sign by external signer
	sig, err := s.signer.Sign(hash)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Alg doesn't need to be implemented.
func (s *remoteSigningMethod) Alg() string {
	alg, err := extractJwtAlgorithm(s.signer)
	if err != nil {
		panic(err)
	}
	return alg
}

// verifyJWT verifies the JWT token against the specified verification key
func verifyJWT(tokenString string, cert *x509.Certificate) error {
	keySpec, err := signature.ExtractKeySpec(cert)
	if err != nil {
		return err
	}
	jwsAlg, err := convertAlgorithm(keySpec.SignatureAlgorithm())
	if err != nil {
		return err
	}
	signingMethod := jwt.GetSigningMethod(jwsAlg)

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}),
		jwt.WithJSONNumber(),
		jwt.WithoutClaimsValidation(),
	)

	if _, err := parser.ParseWithClaims(tokenString, &jwtPayload{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != signingMethod.Alg() {
			return nil, &signature.MalformedSignatureError{
				Msg: fmt.Sprintf("unexpected signing method: %v: require %v", t.Method.Alg(), signingMethod.Alg())}
		}

		// override default signing method with key-specific method
		t.Method = signingMethod
		return cert.PublicKey, nil
	}); err != nil {
		return &signature.SignatureIntegrityError{Err: err}
	}
	return nil
}

func extractJwtAlgorithm(signer signature.Signer) (string, error) {
	keySpec, err := signer.KeySpec()
	if err != nil {
		return "", err
	}
	return convertAlgorithm(keySpec.SignatureAlgorithm())
}

// convertAlgorithm converts the signature.Algorithm to be jwt package defined
// algorithm name.
func convertAlgorithm(alg signature.Algorithm) (string, error) {
	jwsAlg, ok := signatureAlgJWSAlgMap[alg]
	if !ok {
		return "", &signature.SignatureAlgoNotSupportedError{
			Alg: fmt.Sprintf("#%d", alg)}
	}
	return jwsAlg, nil
}
