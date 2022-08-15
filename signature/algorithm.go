package signature

import (
	"crypto"
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

// Hash returns the hash function of the algorithm
func (alg Algorithm) Hash() crypto.Hash {
	switch alg {
	case AlgorithmPS256, AlgorithmES256:
		return crypto.SHA256
	case AlgorithmPS384, AlgorithmES384:
		return crypto.SHA384
	case AlgorithmPS512, AlgorithmES512:
		return crypto.SHA512
	}
	return 0
}

// ExtractKeySpec extracts keySpec from the signing certificate
func ExtractKeySpec(signingCert *x509.Certificate) (KeySpec, error) {
	switch key := signingCert.PublicKey.(type) {
	case *rsa.PublicKey:
		switch bitSize := key.Size() << 3; bitSize {
		case 2048, 3072, 4096:
			return KeySpec{
				Type: KeyTypeRSA,
				Size: bitSize,
			}, nil
		default:
			return KeySpec{}, &UnsupportedSigningKeyError{
				fmt.Sprintf("rsa key size %d is not supported", bitSize),
			}
		}
	case *ecdsa.PublicKey:
		switch bitSize := key.Curve.Params().BitSize; bitSize {
		case 256, 384, 521:
			return KeySpec{
				Type: KeyTypeEC,
				Size: bitSize,
			}, nil
		default:
			return KeySpec{}, &UnsupportedSigningKeyError{
				fmt.Sprintf("ecdsa key size %d is not supported", bitSize),
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
			return AlgorithmPS384
		case 4096:
			return AlgorithmPS512
		}
	}
	return 0
}
