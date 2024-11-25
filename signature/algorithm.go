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
	"crypto/x509"

	"github.com/notaryproject/notation-core-go/internal/algorithm"
)

// Algorithm defines the signature algorithm.
type Algorithm int

// Signature algorithms supported by this library.
//
// Reference: https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
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
	// KeyType is the type of the key.
	Type KeyType

	// KeySize is the size of the key in bits.
	Size int
}

// Hash returns the hash function of the algorithm.
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

// ExtractKeySpec extracts KeySpec from the signing certificate.
func ExtractKeySpec(signingCert *x509.Certificate) (KeySpec, error) {
	ks, err := algorithm.ExtractKeySpec(signingCert)
	if err != nil {
		return KeySpec{}, &UnsupportedSigningKeyError{
			Msg: err.Error(),
		}
	}
	return KeySpec{
		Type: KeyType(ks.Type),
		Size: ks.Size,
	}, nil
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
