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

func TestMethods(t *testing.T) {
	t.Run("MethodUnknown", func(t *testing.T) {
		if MethodUnknown != 0 {
			t.Errorf("Expected %d but got %d", 0, MethodUnknown)
		}
	})
	t.Run("MethodOCSP", func(t *testing.T) {
		if MethodOCSP != 1 {
			t.Errorf("Expected %d but got %d", 1, MethodOCSP)
		}
	})
	t.Run("MethodCRL", func(t *testing.T) {
		if MethodCRL != 2 {
			t.Errorf("Expected %d but got %d", 1, MethodCRL)
		}
	})
	t.Run("MethodOCSPFallbackCRL", func(t *testing.T) {
		if MethodOCSPFallbackCRL != 3 {
			t.Errorf("Expected %d but got %d", 3, MethodOCSPFallbackCRL)
		}
	})
}
