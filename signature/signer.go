// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// LocalSigner is only used by built-in signers to sign.
type LocalSigner interface {
	Signer

	// CertificateChain returns the certificate chain.
	CertificateChain() ([]*x509.Certificate, error)

	// PrivateKey returns the private key.
	PrivateKey() crypto.PrivateKey
}

// localSigner implements LocalSigner interface.
//
// Note that localSigner only holds the signing key, keySpec and certificate
// chain. The underlying signing implementation is provided by the underlying
// crypto library for the specific signature format like go-jwt or go-cose.
type localSigner struct {
	keySpec KeySpec
	key     crypto.PrivateKey
	certs   []*x509.Certificate
}

// NewLocalSigner returns a new signer with given certificates and private key.
func NewLocalSigner(certs []*x509.Certificate, key crypto.PrivateKey) (LocalSigner, error) {
	if len(certs) == 0 {
		return nil, &InvalidArgumentError{
			Param: "certs",
			Err:   errors.New("empty certs"),
		}
	}

	keySpec, err := ExtractKeySpec(certs[0])
	if err != nil {
		return nil, err
	}

	if !isKeyPair(key, certs[0].PublicKey, keySpec) {
		return nil, &InvalidArgumentError{
			Param: "key and certs",
			Err:   errors.New("key not matches certificate"),
		}
	}

	return &localSigner{
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

// Sign signs the content and returns the raw signature and certificates.
// This implementation should never be used by built-in signers.
func (s *localSigner) Sign(content []byte) ([]byte, []*x509.Certificate, error) {
	return nil, nil, fmt.Errorf("local signer doesn't support sign")
}

// KeySpec returns the key specification.
func (s *localSigner) KeySpec() (KeySpec, error) {
	return s.keySpec, nil
}

// CertificateChain returns the certificate chain.
func (s *localSigner) CertificateChain() ([]*x509.Certificate, error) {
	return s.certs, nil
}

// PrivateKey returns the private key.
func (s *localSigner) PrivateKey() crypto.PrivateKey {
	return s.key
}

// VerifyAuthenticity iterates the certificate chain in signerInfo, for each
// certificate in the chain, it checks if the certificate matches with one of
// the trusted certificates in trustedCerts. It returns the first matching
// certificate. If no match is found, it returns an error.
//
// Reference: https://github.com/notaryproject/notaryproject/blob/main/specs/trust-store-trust-policy.md#steps
func VerifyAuthenticity(signerInfo *SignerInfo, trustedCerts []*x509.Certificate) (*x509.Certificate, error) {
	if len(trustedCerts) == 0 {
		return nil, &InvalidArgumentError{Param: "trustedCerts"}
	}
	if signerInfo == nil {
		return nil, &InvalidArgumentError{Param: "signerInfo"}
	}
	for _, cert := range signerInfo.CertificateChain {
		for _, trust := range trustedCerts {
			if trust.Equal(cert) {
				return trust, nil
			}
		}
	}
	return nil, &SignatureAuthenticityError{}
}
