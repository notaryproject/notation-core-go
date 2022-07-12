package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

// GetKeySpec picks up a recommended signing algorithm for given certificate.
func GetKeySpec(signingCert *x509.Certificate) (KeySpec, error) {
	var keyspec KeySpec
	switch key := signingCert.PublicKey.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			keyspec = RSA_2048
		case 384:
			keyspec = RSA_3072
		case 512:
			keyspec = RSA_4096
		default:
			return "", UnsupportedSigningKeyError{keyType: "rsa", keyLength: key.Size()}
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			keyspec = EC_256
		case 384:
			keyspec = EC_384
		case 521:
			keyspec = EC_521
		default:
			return "", UnsupportedSigningKeyError{keyType: "ecdsa", keyLength: key.Curve.Params().BitSize}
		}
	}
	return keyspec, nil
}

// NewLocalSignatureProvider returns the LocalSignatureProvider created using given certificates and private key.
func NewLocalSignatureProvider(certs []*x509.Certificate, pk crypto.PrivateKey) (*LocalSignatureProvider, error) {
	if len(certs) == 0 {
		return nil, MalformedArgumentError{param: "certs"}
	}

	ks, err := GetKeySpec(certs[0])
	if err != nil {
		return nil, err
	}

	return &LocalSignatureProvider{
		key:     pk,
		certs:   certs,
		keySpec: ks,
	}, nil
}

// LocalSignatureProvider implements SignatureEnvelope's SignatureProvider to facilitate signing using local certificates and private key.
type LocalSignatureProvider struct {
	keySpec KeySpec
	key     crypto.PrivateKey
	certs  []*x509.Certificate
}

func (l *LocalSignatureProvider) Sign(bytes []byte) ([]byte, []*x509.Certificate, error) {
	// calculate hash
	hasher := l.keySpec.SignatureAlgorithm().Hash()
	h := hasher.New()
	h.Write(bytes)
	hash := h.Sum(nil)

	// sign
	switch key := l.key.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand.Reader, key, hasher.HashFunc(), hash, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return nil, nil, err
		}
		return sig, l.certs, nil
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			return nil, nil, err
		}

		curveBits := key.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		out := make([]byte, 2*keyBytes)
		r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
		s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.
		return out, l.certs, nil
	}

	return nil, nil, UnsupportedSigningKeyError{}
}

func (l *LocalSignatureProvider) KeySpec() (KeySpec, error) {
	return l.keySpec, nil
}

// getSignatureAlgorithm picks up a recommended signing algorithm for given certificate.
func getSignatureAlgorithm(signingCert *x509.Certificate) (SignatureAlgorithm, error) {
	keySpec, err := GetKeySpec(signingCert)
	if err != nil {
		return "", err
	}

	return keySpec.SignatureAlgorithm(), nil
}
