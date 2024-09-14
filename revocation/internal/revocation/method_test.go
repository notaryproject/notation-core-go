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

package revocation

import "testing"

func TestMethodString(t *testing.T) {
	tests := []struct {
		method   Method
		expected string
	}{
		{MethodOCSP, "OCSP"},
		{MethodCRL, "CRL"},
		{MethodOCSPFallbackCRL, "OCSPFallbackCRL"},
		{Method(999), "Unknown"}, // Test for default case
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.method.String()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}
