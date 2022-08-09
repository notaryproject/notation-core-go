package signature

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
)

// Algorithm lists supported algorithms.
type Algorithm int

// One of following supported specs
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	AlgorithmPS256 Algorithm = 1 + iota // RSASSA_PSS_SHA256
	AlgorithmPS384                      // RSASSA_PSS_SHA384
	AlgorithmPS512                      // RSASSA_PSS_SHA512
	AlgorithmES256                      // ECDSA_SHA256
	AlgorithmES384                      // ECDSA_SHA384
	AlgorithmES512                      // ECDSA_SHA512
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

func newKeySpec(keyType KeyType, size int) KeySpec {
	return KeySpec{
		Type: keyType,
		Size: size,
	}
}

// ExtractKeySpec extracts keySpec from the signing certificate
func ExtractKeySpec(signingCert *x509.Certificate) (KeySpec, error) {
	var keySpec KeySpec
	switch key := signingCert.PublicKey.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			keySpec = newKeySpec(KeyTypeRSA, 2048)
		case 384:
			keySpec = newKeySpec(KeyTypeRSA, 3072)
		case 512:
			keySpec = newKeySpec(KeyTypeRSA, 4096)
		default:
			return KeySpec{}, UnsupportedSigningKeyError{
				keyType:   KeyTypeRSA,
				keyLength: key.Size(),
			}
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			keySpec = newKeySpec(KeyTypeEC, 256)
		case 384:
			keySpec = newKeySpec(KeyTypeEC, 384)
		case 521:
			keySpec = newKeySpec(KeyTypeEC, 521)
		default:
			return KeySpec{}, UnsupportedSigningKeyError{
				keyType:   KeyTypeEC,
				keyLength: key.Curve.Params().BitSize,
			}
		}
	}
	return keySpec, nil
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
