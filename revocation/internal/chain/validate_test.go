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

package chain

import (
	"crypto/x509"
	"testing"

	"github.com/notaryproject/notation-core-go/revocation/purpose"
	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestValidate(t *testing.T) {
	t.Run("unsupported_certificate_chain_purpose", func(t *testing.T) {
		certChain := []*x509.Certificate{}
		certChainPurpose := purpose.Purpose(-1)
		err := Validate(certChain, certChainPurpose)
		if err == nil {
			t.Errorf("Validate() failed, expected error, got nil")
		}
	})

	t.Run("invalid code signing certificate chain", func(t *testing.T) {
		certChain := []*x509.Certificate{}
		certChainPurpose := purpose.CodeSigning
		err := Validate(certChain, certChainPurpose)
		if err == nil {
			t.Errorf("Validate() failed, expected error, got nil")
		}
	})

	t.Run("invalid timestamping certificate chain", func(t *testing.T) {
		certChain := []*x509.Certificate{}
		certChainPurpose := purpose.Timestamping
		err := Validate(certChain, certChainPurpose)
		if err == nil {
			t.Errorf("Validate() failed, expected error, got nil")
		}
	})

	t.Run("valid code signing certificate chain", func(t *testing.T) {
		certChain := testhelper.GetRevokableRSAChain(2)
		certChainPurpose := purpose.CodeSigning
		err := Validate([]*x509.Certificate{certChain[0].Cert, certChain[1].Cert}, certChainPurpose)
		if err != nil {
			t.Errorf("Validate() failed, expected nil, got %v", err)
		}
	})
}
