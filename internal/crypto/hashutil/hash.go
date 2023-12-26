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

// Package hashutil provides utilities for hash.
package hashutil

import (
	"crypto"
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
