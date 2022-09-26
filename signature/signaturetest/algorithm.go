package signaturetest

import "github.com/notaryproject/notation-core-go/signature"

// KeyTypes contains supported key type.
var KeyTypes = []signature.KeyType{signature.KeyTypeRSA, signature.KeyTypeEC}

// GetKeySizes returns the supported key size for the named keyType.
func GetKeySizes(keyType signature.KeyType) []int {
	switch keyType {
	case signature.KeyTypeRSA:
		return []int{2048, 3072, 4096}
	case signature.KeyTypeEC:
		return []int{256, 384, 521}
	default:
		return nil
	}
}
