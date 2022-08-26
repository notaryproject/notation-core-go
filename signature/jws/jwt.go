package jws

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signature"
)

// signingMethod is the interface for jwt.SigingMethod with additional method to
// access certificate chain after calling Sign()
type signingMethod interface {
	jwt.SigningMethod

	// CertificateChain returns the certificate chain.
	//
	// should be called after calling Sign()
	CertificateChain() ([]*x509.Certificate, error)

	// PrivateKey returns the private key.
	PrivateKey() crypto.PrivateKey
}

// remoteSigningMethod wraps the remote signer to be a SigningMethod
type remoteSigningMethod struct {
	signer    signature.Signer
	certs     []*x509.Certificate
	algorithm string
}

func newRemoteSigningMethod(signer signature.Signer) (signingMethod, error) {
	algorithm, err := extractJwtAlgorithm(signer)
	if err != nil {
		return nil, err
	}
	return &remoteSigningMethod{
		signer:    signer,
		algorithm: algorithm,
	}, nil
}

// Verify doesn't need to be implemented.
func (s *remoteSigningMethod) Verify(signingString, signature string, key interface{}) error {
	panic("not implemented")
}

// Sign hashes the signingString and call the remote signer to sign the digest.
func (s *remoteSigningMethod) Sign(signingString string, key interface{}) (string, error) {
	// sign by external signer
	sig, certs, err := s.signer.Sign([]byte(signingString))
	if err != nil {
		return "", err
	}
	s.certs = certs
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Alg return the signing algorithm
func (s *remoteSigningMethod) Alg() string {
	return s.algorithm
}

// CertificateChain returns the certificate chain
//
// should be called after Sign()
func (s *remoteSigningMethod) CertificateChain() ([]*x509.Certificate, error) {
	if s.certs == nil {
		return nil, &signature.RemoteSigningError{Msg: "certificate chain is not set"}
	}
	return s.certs, nil
}

// PrivateKey returns nil for remote signer
func (s *remoteSigningMethod) PrivateKey() crypto.PrivateKey {
	return nil
}

// localSigningMethod wraps the local signer to be a SigningMethod
type localSigningMethod struct {
	jwt.SigningMethod
	signer signature.LocalSigner
	certs  []*x509.Certificate
}

func newLocalSigningMethod(signer signature.LocalSigner) (signingMethod, error) {
	alg, err := extractJwtAlgorithm(signer)
	if err != nil {
		return nil, err
	}

	return &localSigningMethod{
		SigningMethod: jwt.GetSigningMethod(alg),
		signer:        signer,
	}, nil
}

// CertificateChain returns the certificate chain
func (s *localSigningMethod) CertificateChain() ([]*x509.Certificate, error) {
	return s.signer.CertificateChain()
}

// PrivateKey returns the private key
func (s *localSigningMethod) PrivateKey() crypto.PrivateKey {
	return s.signer.PrivateKey()
}

// getSigningMethod return signingMethod for the given signer
func getSigningMethod(signer signature.Signer) (signingMethod, error) {
	if localSigner, ok := signer.(signature.LocalSigner); ok {
		// for local signer
		return newLocalSigningMethod(localSigner)
	}
	// for remote signer
	return newRemoteSigningMethod(signer)
}

// verifyJWT verifies the JWT token against the specified verification key
func verifyJWT(tokenString string, publicKey interface{}) error {
	parser := jwt.NewParser(
		jwt.WithValidMethods(validMethods),
		jwt.WithJSONNumber(),
		jwt.WithoutClaimsValidation(),
	)

	if _, err := parser.ParseWithClaims(tokenString, &jwtPayload{}, func(t *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}); err != nil {
		return &signature.SignatureIntegrityError{Err: err}
	}
	return nil
}

func extractJwtAlgorithm(signer signature.Signer) (string, error) {
	// extract algorithm from signer
	keySpec, err := signer.KeySpec()
	if err != nil {
		return "", err
	}
	alg := keySpec.SignatureAlgorithm()

	// converts the signature.Algorithm to be jwt package defined
	// algorithm name.
	jwsAlg, ok := signatureAlgJWSAlgMap[alg]
	if !ok {
		return "", &signature.SignatureAlgoNotSupportedError{
			Alg: fmt.Sprintf("#%d", alg)}
	}
	return jwsAlg, nil
}
