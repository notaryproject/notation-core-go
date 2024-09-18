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

package cache

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestValidate(t *testing.T) {
	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}
	base, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse base CRL: %v", err)
	}

	t.Run("missing BaseCRL", func(t *testing.T) {
		var bundle Bundle
		if err := bundle.Validate(); err.Error() != "base CRL is missing" {
			t.Fatalf("expected base CRL is missing, got %v", err)
		}
	})

	t.Run("missing metadata baseCRL URL", func(t *testing.T) {
		bundle := Bundle{
			BaseCRL: base,
		}
		if err := bundle.Validate(); err.Error() != "base CRL URL is missing" {
			t.Fatalf("expected base CRL URL is missing, got %v", err)
		}
	})

	t.Run("missing metadata cachedAt", func(t *testing.T) {
		bundle := Bundle{
			BaseCRL: base,
			Metadata: Metadata{
				BaseCRL: CRLMetadata{
					URL: "http://example.com",
				},
			},
		}
		if err := bundle.Validate(); err.Error() != "base CRL CachedAt is missing" {
			t.Fatalf("expected base CRL CachedAt is missing, got %v", err)
		}
	})
}
