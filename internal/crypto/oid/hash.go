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

package oid

import (
	"crypto"
	"encoding/asn1"
)

// ToHash converts ASN.1 digest algorithm identifier to golang crypto hash
// if it is available.
func ToHash(alg asn1.ObjectIdentifier) (crypto.Hash, bool) {
	var hash crypto.Hash
	switch {
	case SHA256.Equal(alg):
		hash = crypto.SHA256
	case SHA384.Equal(alg):
		hash = crypto.SHA384
	case SHA512.Equal(alg):
		hash = crypto.SHA512
	default:
		return hash, false
	}
	return hash, hash.Available()
}
