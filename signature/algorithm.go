package signature

import (
	"crypto/x509"
	"fmt"
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

func ExtractKeySpec(signingCert *x509.Certificate) (KeySpec, error) {
	return KeySpec{}, fmt.Errorf("not implemented")
}
