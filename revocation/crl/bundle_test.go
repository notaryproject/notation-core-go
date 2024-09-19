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

package crl

import (
	"testing"
)

func TestValidate(t *testing.T) {
	t.Run("missing BaseCRL", func(t *testing.T) {
		var bundle Bundle
		if err := bundle.Validate(); err.Error() != "base CRL is missing" {
			t.Fatalf("expected base CRL is missing, got %v", err)
		}
	})
}
