package signature

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// Algorithm lists supported algorithms.
type Algorithm int

// One of following supported specs
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	AlgorithmPS256 Algorithm = 1 + iota // RSASSA-PSS with SHA-256
	AlgorithmPS384                      // RSASSA-PSS with SHA-384
	AlgorithmPS512                      // RSASSA-PSS with SHA-512
	AlgorithmES256                      // ECDSA on secp256r1 with SHA-256
	AlgorithmES384                      // ECDSA on secp384r1 with SHA-384
	AlgorithmES512                      // ECDSA on secp521r1 with SHA-512
)

// KeyType defines the key type
type KeyType int

const (
	KeyTypeRSA KeyType = 1 + iota // KeyType RSA
	KeyTypeEC                     // KeyType EC
)

// KeySpec defines a key type and size.
type KeySpec struct {
	Type KeyType
	Size int
}

// ExtractKeySpec extracts keySpec from the signing certificate
func ExtractKeySpec(signingCert *x509.Certificate) (KeySpec, error) {
	switch key := signingCert.PublicKey.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return KeySpec{
				Type: KeyTypeRSA,
				Size: 2048,
			}, nil
		case 384:
			return KeySpec{
				Type: KeyTypeRSA,
				Size: 3072,
			}, nil
		case 512:
			return KeySpec{
				Type: KeyTypeRSA,
				Size: 4096,
			}, nil
		default:
			return KeySpec{}, UnsupportedSigningKeyError{
				fmt.Sprintf("rsa algorithm of size %d is not supported", key.Size()),
			}
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			return KeySpec{
				Type: KeyTypeEC,
				Size: 256,
			}, nil
		case 384:
			return KeySpec{
				Type: KeyTypeEC,
				Size: 384,
			}, nil
		case 521:
			return KeySpec{
				Type: KeyTypeEC,
				Size: 521,
			}, nil
		default:
			return KeySpec{}, UnsupportedSigningKeyError{
				fmt.Sprintf("ecdsa algorithm of size %d is not supported", key.Curve.Params().BitSize),
			}
		}
	}
	return KeySpec{}, fmt.Errorf("invalid public key type")
}

// SignatureAlgorithm returns the signing algorithm associated with KeyType k.
func (k KeySpec) SignatureAlgorithm() Algorithm {
	switch k.Type {
	case KeyTypeEC:
		switch k.Size {
		case 256:
			return AlgorithmES256
		case 384:
			return AlgorithmES384
		case 521:
			return AlgorithmES512
		}
	case KeyTypeRSA:
		switch k.Size {
		case 2048:
			return AlgorithmPS256
		case 3072:
			return AlgorithmES384
		case 4096:
			return AlgorithmES512
		}
	}
	return 0
}
