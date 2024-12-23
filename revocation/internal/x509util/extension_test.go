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

package x509util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestFindExtensionByOID(t *testing.T) {
	oid1 := asn1.ObjectIdentifier{1, 2, 3, 4}
	oid2 := asn1.ObjectIdentifier{1, 2, 3, 5}
	extensions := []pkix.Extension{
		{Id: oid1, Value: []byte("value1")},
		{Id: oid2, Value: []byte("value2")},
	}

	tests := []struct {
		name       string
		oid        asn1.ObjectIdentifier
		extensions []pkix.Extension
		expected   *pkix.Extension
	}{
		{
			name:       "Extension found",
			oid:        oid1,
			extensions: extensions,
			expected:   &extensions[0],
		},
		{
			name:       "Extension not found",
			oid:        asn1.ObjectIdentifier{1, 2, 3, 6},
			extensions: extensions,
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindExtensionByOID(tt.oid, tt.extensions)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
