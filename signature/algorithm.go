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
	"crypto/x509"

	"github.com/notaryproject/notation-core-go/internal/algorithm"
)

// Algorithm defines the signature algorithm.
type Algorithm = algorithm.Algorithm

// Signature algorithms supported by this library.
//
// Reference: https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
const (
	AlgorithmPS256 = algorithm.AlgorithmPS256 // RSASSA-PSS with SHA-256
	AlgorithmPS384 = algorithm.AlgorithmPS384 // RSASSA-PSS with SHA-384
	AlgorithmPS512 = algorithm.AlgorithmPS512 // RSASSA-PSS with SHA-512
	AlgorithmES256 = algorithm.AlgorithmES256 // ECDSA on secp256r1 with SHA-256
	AlgorithmES384 = algorithm.AlgorithmES384 // ECDSA on secp384r1 with SHA-384
	AlgorithmES512 = algorithm.AlgorithmES512 // ECDSA on secp521r1 with SHA-512
)

// KeyType defines the key type.
type KeyType = algorithm.KeyType

const (
	KeyTypeRSA = algorithm.KeyTypeRSA // KeyType RSA
	KeyTypeEC  = algorithm.KeyTypeEC  // KeyType EC
)

// KeySpec defines a key type and size.
type KeySpec = algorithm.KeySpec

// ExtractKeySpec extracts KeySpec from the signing certificate.
func ExtractKeySpec(signingCert *x509.Certificate) (KeySpec, error) {
	ks, err := algorithm.ExtractKeySpec(signingCert)
	if err != nil {
		return KeySpec{}, &UnsupportedSigningKeyError{
			Msg: err.Error(),
		}
	}
	return ks, nil
}
