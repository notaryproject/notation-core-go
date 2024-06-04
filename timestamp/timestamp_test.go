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
	"context"
	"crypto"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/tspclient-go"
	"github.com/notaryproject/tspclient-go/pki"
)

func TestTimestamp(t *testing.T) {
	ctx := context.Background()
	testResp, err := os.ReadFile("testdata/granted.tsq")
	if err != nil {
		t.Fatal("failed to read test response:", err)
	}

	// --------------- Success case ----------------------------------
	opts := tspclient.RequestOptions{
		Content:                 []byte("notation"),
		HashAlgorithm:           crypto.SHA256,
		HashAlgorithmParameters: asn1.NullRawValue,
	}
	mockValidTSA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = tspclient.TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", tspclient.TimestampReply)
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer mockValidTSA.Close()
	_, err = Timestamp(ctx, mockValidTSA.URL, nil, opts)
	if err != nil {
		t.Fatal(err)
	}

	// ------------- Failure cases ------------------------
	opts = tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA1,
	}
	expectedErr := "malformed timestamping request: unsupported hashing algorithm: SHA-1"
	_, err = Timestamp(ctx, "", nil, opts)
	assertErrorEqual(expectedErr, err, t)

	opts = tspclient.RequestOptions{
		Content:                 []byte("notation"),
		HashAlgorithm:           crypto.SHA256,
		HashAlgorithmParameters: asn1.NullRawValue,
	}
	bs, err := hex.DecodeString("7f")
	if err != nil {
		t.Fatal(err)
	}
	expectedErr = "parse \"http://\\x7f\": net/url: invalid control character in URL"
	_, err = Timestamp(ctx, "http://"+string(bs), nil, opts)
	assertErrorEqual(expectedErr, err, t)

	mockInvalidTSA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = tspclient.TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", tspclient.TimestampReply)
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer mockInvalidTSA.Close()
	expectedErr = "https response bad status: 500 Internal Server Error"
	_, err = Timestamp(ctx, mockInvalidTSA.URL, nil, opts)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error message to contain %s, but got %v", expectedErr, err)
	}

	opts = tspclient.RequestOptions{
		Content:                 []byte("notation"),
		HashAlgorithm:           crypto.SHA256,
		HashAlgorithmParameters: asn1.NullRawValue,
	}
	mockInvalidTSA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = tspclient.TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		token, err := os.ReadFile("testdata/TimeStampTokenWithoutCertificate.p7s")
		if err != nil {
			t.Fatal(err)
		}
		resp := &tspclient.Response{
			Status: pki.StatusInfo{
				Status: pki.StatusGranted,
			},
			TimeStampToken: asn1.RawValue{
				FullBytes: token,
			},
		}
		respBytes, err := resp.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", tspclient.TimestampReply)
		if _, err := w.Write(respBytes); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer mockInvalidTSA.Close()
	expectedErr = "no valid timestamp signing certificate was found in timestamp token"
	_, err = Timestamp(ctx, mockInvalidTSA.URL, nil, opts)
	assertErrorEqual(expectedErr, err, t)

	opts = tspclient.RequestOptions{
		Content:                 []byte("notation"),
		HashAlgorithm:           crypto.SHA256,
		HashAlgorithmParameters: asn1.NullRawValue,
	}
	mockInvalidTSA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = tspclient.TimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimeStampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimeStampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", tspclient.TimestampReply)
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer mockInvalidTSA.Close()
	signingTime := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	expectedErr = "no valid timestamp signing certificate was found in timestamp token"
	_, err = Timestamp(ctx, mockInvalidTSA.URL, &signingTime, opts)
	assertErrorEqual(expectedErr, err, t)
}

func TestGenerateNonce(t *testing.T) {
	if _, err := GenerateNonce(); err != nil {
		t.Fatal(err)
	}
}

func assertErrorEqual(expected string, err error, t *testing.T) {
	if err == nil || expected != err.Error() {
		t.Fatalf("Expected error \"%v\" but was \"%v\"", expected, err)
	}
}
