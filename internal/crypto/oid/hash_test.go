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
	"testing"
)

func TestToHash(t *testing.T) {
	tests := []struct {
		name       string
		alg        asn1.ObjectIdentifier
		wantHash   crypto.Hash
		wantExists bool
	}{
		{"SHA256", SHA256, crypto.SHA256, true},
		{"SHA384", SHA384, crypto.SHA384, true},
		{"SHA512", SHA512, crypto.SHA512, true},
		{"Unknown", asn1.ObjectIdentifier{1, 2, 3}, crypto.Hash(0), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHash, gotExists := ToHash(tt.alg)
			if gotHash != tt.wantHash {
				t.Errorf("ToHash() gotHash = %v, want %v", gotHash, tt.wantHash)
			}
			if gotExists != tt.wantExists {
				t.Errorf("ToHash() gotExists = %v, want %v", gotExists, tt.wantExists)
			}
		})
	}
}
