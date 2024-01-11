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
	"crypto/sha256"
	"testing"
)

func TestComputeHash(t *testing.T) {
	message := []byte("test message")
	expectedHash := sha256.Sum256(message)

	hash, err := ComputeHash(crypto.SHA256, message)
	if err != nil {
		t.Fatalf("ComputeHash returned an error: %v", err)
	}

	if string(hash) != string(expectedHash[:]) {
		t.Errorf("ComputeHash returned incorrect hash: got %x, want %x", hash, expectedHash)
	}
}
