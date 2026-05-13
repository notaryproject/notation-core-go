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

package pkcs7

import (
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
)

func FuzzSignaturePkcs7(f *testing.F) {
	// Seed the corpus with a known-good envelope.
	seed, err := NewEnvelope().Sign(&signature.SignRequest{
		Payload: signature.Payload{ContentType: MediaTypeEnvelope, Content: []byte(testPayload)},
		Signer:  newRSATestSigner(),
	})
	if err != nil {
		f.Fatalf("seed Sign() error: %v", err)
	}
	f.Add(seed, true)
	f.Add(seed, false)

	f.Fuzz(func(t *testing.T, envelopeBytes []byte, shouldVerify bool) {
		e, err := ParseEnvelope(envelopeBytes)
		if err != nil {
			t.Skip()
		}

		if shouldVerify {
			_, _ = e.Verify()
		} else {
			_, _ = e.Content()
		}
	})
}
