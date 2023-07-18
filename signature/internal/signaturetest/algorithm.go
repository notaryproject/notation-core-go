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

// Package signaturetest includes variables and functions for signature
// unit test.
package signaturetest

import "github.com/notaryproject/notation-core-go/signature"

// KeyTypes contains supported key type
var KeyTypes = []signature.KeyType{signature.KeyTypeRSA, signature.KeyTypeEC}

// GetKeySizes returns the supported key size for the named keyType
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
