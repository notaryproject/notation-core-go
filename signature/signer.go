package signature

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

// Signer is used to sign bytes generated after creating signature envelope.
type Signer interface {
	Sign(digest []byte) ([]byte, error)
	CertificateChain() ([]*x509.Certificate, error) // note: check signature first
	KeySpec() (KeySpec, error)
}

type LocalSigner interface {
	Signer
	PrivateKey() crypto.PrivateKey
}

type signer struct {
	keySpec KeySpec
	key     crypto.PrivateKey
	certs   []*x509.Certificate
}

func NewSigner(certs []*x509.Certificate, key crypto.PrivateKey) (Signer, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *signer) Sign(digest []byte) ([]byte, error) {
	return nil, fmt.Errorf("local signer doesn't support Sign with digest")
}

func (s *signer) CertificateChain() ([]*x509.Certificate, error) {
	return s.certs, nil
}

func (s *signer) KeySpec() (KeySpec, error) {
	return s.keySpec, nil
}

func (s *signer) PrivateKey() crypto.PrivateKey {
	return s.key
}
