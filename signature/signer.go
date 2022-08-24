package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// Signer is used to sign bytes generated after signature envelope created.
type Signer interface {
	// Sign signs the payload and returns the raw signature and certificates.
	Sign(payload []byte) ([]byte, []*x509.Certificate, error)

	// KeySpec returns the key specification.
	KeySpec() (KeySpec, error)
}

// LocalSigner is used by built-in signers to sign only.
type LocalSigner interface {
	Signer

	// CertificateChain returns the certificate chain.
	CertificateChain() ([]*x509.Certificate, error)

	// PrivateKey returns the private key.
	PrivateKey() crypto.PrivateKey
}

// signer is a LocalSigner implementation.
type signer struct {
	keySpec KeySpec
	key     crypto.PrivateKey
	certs   []*x509.Certificate
}

// NewLocalSigner returns a new signer with given certificates and private key.
func NewLocalSigner(certs []*x509.Certificate, key crypto.PrivateKey) (LocalSigner, error) {
	if len(certs) == 0 {
		return nil, &MalformedArgumentError{
			Param: "certs",
			Err:   errors.New("empty certs"),
		}
	}

	keySpec, err := ExtractKeySpec(certs[0])
	if err != nil {
		return nil, err
	}

	if !isKeyPair(key, certs[0].PublicKey, keySpec) {
		return nil, &MalformedArgumentError{
			Param: "key and certs",
			Err:   errors.New("key not matches certificate"),
		}
	}

	return &signer{
		keySpec: keySpec,
		key:     key,
		certs:   certs,
	}, nil
}

// isKeyPair checks if the private key matches the provided public key.
func isKeyPair(priv crypto.PrivateKey, pub crypto.PublicKey, keySpec KeySpec) bool {
	switch keySpec.Type {
	case KeyTypeRSA:
		privateKey, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return false
		}
		return privateKey.PublicKey.Equal(pub)
	case KeyTypeEC:
		privateKey, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return false
		}
		return privateKey.PublicKey.Equal(pub)
	default:
		return false
	}
}

// Sign signs the digest and returns the raw signature and certificates.
// This implementation should never be used by built-in signers.
func (s *signer) Sign(digest []byte) ([]byte, []*x509.Certificate, error) {
	return nil, nil, fmt.Errorf("local signer doesn't support sign with digest")
}

// KeySpec returns the key specification.
func (s *signer) KeySpec() (KeySpec, error) {
	return s.keySpec, nil
}

// CertificateChain returns the certificate chain.
func (s *signer) CertificateChain() ([]*x509.Certificate, error) {
	return s.certs, nil
}

// PrivateKey returns the private key.
func (s *signer) PrivateKey() crypto.PrivateKey {
	return s.key
}

// VerifyAuthenticity verifies the certificate chain in the given SignerInfo
// with one of the trusted certificates and returns a certificate that matches
// with one of the certificates in the SignerInfo.
//
// Reference: https://github.com/notaryproject/notaryproject/blob/main/trust-store-trust-policy-specification.md#steps
func VerifyAuthenticity(signerInfo *SignerInfo, trustedCerts []*x509.Certificate) (*x509.Certificate, error) {
	if len(trustedCerts) == 0 {
		return nil, &MalformedArgumentError{Param: "trustedCerts"}
	}

	if signerInfo == nil {
		return nil, &MalformedArgumentError{Param: "signerInfo"}
	}

	for _, trust := range trustedCerts {
		for _, sig := range signerInfo.CertificateChain {
			if trust.Equal(sig) {
				return trust, nil
			}
		}
	}
	return nil, &SignatureAuthenticityError{}
}
