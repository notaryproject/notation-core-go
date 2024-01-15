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

package timestamp

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestNewRequest(t *testing.T) {
	message := []byte("test")
	digest := sha256.Sum256(message)

	expectedErrMsg := fmt.Sprintf("unsupported hashing algorithm: %s", crypto.SHA1)
	_, err := NewRequest(digest[:], crypto.SHA1)
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	expectedErrMsg = fmt.Sprintf("digest is of incorrect size: %d", len(digest))
	_, err = NewRequest(digest[:], crypto.SHA384)
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestRequestMarshalBinary(t *testing.T) {
	var r *Request
	_, err := r.MarshalBinary()
	if err == nil || err.Error() != "nil request" {
		t.Fatalf("expected error nil request, but got %v", err)
	}

	message := []byte("notation")
	req, err := NewRequestFromContent(message, crypto.SHA256)
	if err != nil {
		t.Fatalf("NewRequestFromContent() error = %v", err)
	}
	_, err = req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRequestUnmarshalBinary(t *testing.T) {
	var r *Request
	expectedErrMsg := "asn1: Unmarshal recipient value is nil *timestamp.Request"
	err := r.UnmarshalBinary([]byte("test"))
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}
