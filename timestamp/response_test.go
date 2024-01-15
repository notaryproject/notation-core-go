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
	"testing"

	"github.com/notaryproject/notation-core-go/internal/crypto/pki"
)

func TestResponseMarshalBinary(t *testing.T) {
	var r *Response
	_, err := r.MarshalBinary()
	if err == nil || err.Error() != "nil response" {
		t.Fatalf("expected error nil response, but got %v", err)
	}

	testResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
	}
	_, err = (&testResponse).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
}

func TestResponseUnmarshalBinary(t *testing.T) {
	var r *Response
	expectedErrMsg := "asn1: Unmarshal recipient value is nil *timestamp.Response"
	err := r.UnmarshalBinary([]byte("test"))
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}

func TestValidateStatus(t *testing.T) {
	badResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusRejection,
		},
	}
	expectedErrMsg := "invalid response with status code: 2"
	err := (&badResponse).ValidateStatus()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	validResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
	}
	err = (&validResponse).ValidateStatus()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignedToken(t *testing.T) {
	badResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusRejection,
		},
	}
	expectedErrMsg := "invalid response with status code: 2"
	_, err := (&badResponse).SignedToken()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}

	validResponse := Response{
		Status: pki.StatusInfo{
			Status: pki.StatusGranted,
		},
	}
	expectedErrMsg = "cms: syntax error: invalid signed data: failed to convert from BER to DER: asn1: syntax error: BER-encoded ASN.1 data structures is empty"
	_, err = (&validResponse).SignedToken()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected error %s, but got %v", expectedErrMsg, err)
	}
}
