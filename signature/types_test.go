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

package signature

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestSignRequestContext(t *testing.T) {
	r := &SignRequest{
		ctx: context.WithValue(context.Background(), "k1", "v1"),
	}

	ctx := r.Context()
	if ctx.Value("k1") != "v1" {
		t.Fatal("expected k1:v1 in ctx")
	}

	r = &SignRequest{}
	ctx = r.Context()
	if fmt.Sprint(ctx) != "context.Background" {
		t.Fatal("expected context.Background")
	}
}

func TestSignRequestWithContext(t *testing.T) {
	r := &SignRequest{}
	ctx := context.WithValue(context.Background(), "k1", "v1")
	r = r.WithContext(ctx)
	if r.ctx.Value("k1") != "v1" {
		t.Fatal("expected k1:v1 in request ctx")
	}

	defer func() {
		if rc := recover(); rc == nil {
			t.Errorf("expected to be panic")
		}
	}()
	//lint:ignore SA1012 nil context is used for testing
	r.WithContext(nil) // should panic
}

func TestAuthenticSigningTime(t *testing.T) {
	testTime := time.Now()
	signerInfo := SignerInfo{
		SignedAttributes: SignedAttributes{
			SigningScheme: "notary.x509.signingAuthority",
			SigningTime:   testTime,
		},
	}
	authenticSigningTime, err := signerInfo.AuthenticSigningTime()
	if err != nil {
		t.Fatal(err)
	}
	if !authenticSigningTime.Equal(testTime) {
		t.Fatalf("expected %s, but got %s", testTime, authenticSigningTime)
	}

	signerInfo = SignerInfo{
		SignedAttributes: SignedAttributes{
			SigningScheme: "notary.x509.signingAuthority",
		},
	}
	expectedErrMsg := "authentic signing time must be present under signing scheme \"notary.x509.signingAuthority\""
	_, err = signerInfo.AuthenticSigningTime()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}

	signerInfo = SignerInfo{
		SignedAttributes: SignedAttributes{
			SigningScheme: "notary.x509",
		},
	}
	expectedErrMsg = "authentic signing time not supported under signing scheme \"notary.x509\""
	_, err = signerInfo.AuthenticSigningTime()
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}
}
