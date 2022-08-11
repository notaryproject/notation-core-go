package signature

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
)

// Signer is used to sign bytes generated after creating signature envelope.
type Signer interface {
	// Sign signs the digest and returns the raw signature
	Sign(digest []byte) ([]byte, error)
	// CertificateChain returns the certificate chain
	CertificateChain() ([]*x509.Certificate, error) // note: check signature first
	// KeySpec returns the key specification
	KeySpec() (KeySpec, error)
}

// LocalSigner is used by built-in signers to sign only
type LocalSigner interface {
	Signer
	// PrivateKey returns the private key
	PrivateKey() crypto.PrivateKey
}

type signer struct {
	keySpec KeySpec
	key     crypto.PrivateKey
	certs   []*x509.Certificate
}

// NewLocalSigner returns a new signer with certificates and private key
func NewLocalSigner(certs []*x509.Certificate, key crypto.PrivateKey) (LocalSigner, error) {
	if len(certs) == 0 {
		return nil, &MalformedArgumentError{
			Param: "certs",
			Err: errors.New("empty certs"),
		}
	}
	keySpec, err := ExtractKeySpec(certs[0])
	if err != nil {
		return nil, err
	}
	return &signer{
		keySpec: keySpec,
		key:     key,
		certs:   certs,
	}, nil
}

// Sign signs the digest and returns the raw signature
func (s *signer) Sign(digest []byte) ([]byte, error) {
	return nil, fmt.Errorf("local signer doesn't support Sign with digest")
}

// CertificateChain returns the certificate chain
func (s *signer) CertificateChain() ([]*x509.Certificate, error) {
	return s.certs, nil
}

// KeySpec returns the key specification
func (s *signer) KeySpec() (KeySpec, error) {
	return s.keySpec, nil
}

// PrivateKey returns the private key
func (s *signer) PrivateKey() crypto.PrivateKey {
	return s.key
}

// VerifyAuthenticity verifies the certificate chain in the given SignerInfo
// with one of the trusted certificates and returns a certificate that matches
// with one of the certificates in the SignerInfo.
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
