// Package hashutil provides utilities for hash.
package hashutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
)

// ComputeHash computes the digest of the message with the given hash algorithm.
// Callers should check the availability of the hash algorithm before invoking.
func ComputeHash(hash crypto.Hash, message []byte) ([]byte, error) {
	h := hash.New()
	_, err := h.Write(message)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// GetHasher picks up a recommended hashing algorithm for given public keys.
func GetHasher(pubKey crypto.PublicKey) (crypto.Hash, bool) {
	var hash crypto.Hash
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			hash = crypto.SHA256
		case 384:
			hash = crypto.SHA384
		case 512:
			hash = crypto.SHA512
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case 256:
			hash = crypto.SHA256
		case 384:
			hash = crypto.SHA384
		case 521:
			hash = crypto.SHA512
		}
	}
	return hash, hash.Available()
}