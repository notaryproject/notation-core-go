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

package algorithm

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
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

// ExtractKeySpec extracts KeySpec from the signing certificate.
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
			return KeySpec{}, fmt.Errorf("rsa key size %d bits is not supported", bitSize)
		}
	case *ecdsa.PublicKey:
		switch bitSize := key.Curve.Params().BitSize; bitSize {
		case 256, 384, 521:
			return KeySpec{
				Type: KeyTypeEC,
				Size: bitSize,
			}, nil
		default:
			return KeySpec{}, fmt.Errorf("ecdsa key size %d bits is not supported", bitSize)
		}
	}
	return KeySpec{}, errors.New("unsupported public key type")
}
