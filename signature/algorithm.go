package signature

// Algorithm defines the signature algorithm.
type Algorithm int

// Signature algorithms supported by this library.
//
// Reference: https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	AlgorithmPS256 Algorithm = 1 + iota // RSASSA-PSS with SHA-256
	AlgorithmPS384                      // RSASSA-PSS with SHA-384
	AlgorithmPS512                      // RSASSA-PSS with SHA-512
	AlgorithmES256                      // ECDSA on secp256r1 with SHA-256
	AlgorithmES384                      // ECDSA on secp384r1 with SHA-384
	AlgorithmES512                      // ECDSA on secp521r1 with SHA-512
)

// KeyType defines the key type.
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

// SignatureAlgorithm returns the signing algorithm associated with the KeySpec.
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
