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
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/tspclient-go"
	"github.com/notaryproject/tspclient-go/pki"
)

const rfc3161TSAurl = "http://rfc3161timestamp.globalsign.com/advanced"

func TestTimestamp(t *testing.T) {
	ctx := context.Background()
	testResp, err := os.ReadFile("testdata/granted.tsq")
	if err != nil {
		t.Fatal("failed to read test response:", err)
	}
	rootCerts, err := nx509.ReadCertificateFile("testdata/tsaRootCert.crt")
	if err != nil || len(rootCerts) == 0 {
		t.Fatal("failed to read root CA certificate:", err)
	}
	rootCert := rootCerts[0]
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCert)

	// --------------- Success case ----------------------------------
	req := &signature.SignRequest{
		TSAServerURL: rfc3161TSAurl,
		TSARootCAs:   rootCAs,
	}
	opts := tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
	}
	_, err = Timestamp(ctx, req, opts)
	if err != nil {
		t.Fatal(err)
	}

	// ------------- Failure cases ------------------------
	req = &signature.SignRequest{
		TSARootCAs: rootCAs,
	}
	opts = tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA1,
	}
	expectedErr := "malformed timestamping request: unsupported hashing algorithm: SHA-1"
	_, err = Timestamp(ctx, req, opts)
	assertErrorEqual(expectedErr, err, t)

	opts = tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
	}
	bs, err := hex.DecodeString("7f")
	if err != nil {
		t.Fatal(err)
	}
	req = &signature.SignRequest{
		TSAServerURL: "http://" + string(bs),
		TSARootCAs:   rootCAs,
	}
	expectedErr = "parse \"http://\\x7f\": net/url: invalid control character in URL"
	_, err = Timestamp(ctx, req, opts)
	assertErrorEqual(expectedErr, err, t)

	mockInvalidTSA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = tspclient.MediaTypeTimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimestampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimestampRequest.Body read error = %v", err)
		}

		// write reply
		w.Header().Set("Content-Type", tspclient.MediaTypeTimestampReply)
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write(testResp); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer mockInvalidTSA.Close()
	req = &signature.SignRequest{
		TSAServerURL: mockInvalidTSA.URL,
		TSARootCAs:   rootCAs,
	}
	expectedErr = "https response bad status: 500 Internal Server Error"
	_, err = Timestamp(ctx, req, opts)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error message to contain %s, but got %v", expectedErr, err)
	}

	opts = tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		NoNonce:       true,
	}
	mockInvalidTSA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = tspclient.MediaTypeTimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimestampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimestampRequest.Body read error = %v", err)
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
			TimestampToken: asn1.RawValue{
				FullBytes: token,
			},
		}
		respBytes, err := resp.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", tspclient.MediaTypeTimestampReply)
		if _, err := w.Write(respBytes); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer mockInvalidTSA.Close()
	req = &signature.SignRequest{
		TSAServerURL: mockInvalidTSA.URL,
		TSARootCAs:   rootCAs,
	}
	expectedErr = "invalid timestamping response: certReq is True in request, but did not find any TSA signing certificate in the response"
	_, err = Timestamp(ctx, req, opts)
	assertErrorEqual(expectedErr, err, t)

	opts = tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		NoNonce:       true,
	}
	mockInvalidTSA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const wantContentType = tspclient.MediaTypeTimestampQuery
		if got := r.Header.Get("Content-Type"); got != wantContentType {
			t.Fatalf("TimestampRequest.ContentType = %v, want %v", err, wantContentType)
		}
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("TimestampRequest.Body read error = %v", err)
		}

		// write reply
		token, err := os.ReadFile("testdata/TimeStampTokenWithInvalidSignature.p7s")
		if err != nil {
			t.Fatal(err)
		}
		resp := &tspclient.Response{
			Status: pki.StatusInfo{
				Status: pki.StatusGranted,
			},
			TimestampToken: asn1.RawValue{
				FullBytes: token,
			},
		}
		respBytes, err := resp.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", tspclient.MediaTypeTimestampReply)
		if _, err := w.Write(respBytes); err != nil {
			t.Error("failed to write response:", err)
		}
	}))
	defer mockInvalidTSA.Close()
	req = &signature.SignRequest{
		TSAServerURL: mockInvalidTSA.URL,
		TSARootCAs:   rootCAs,
	}
	expectedErr = "failed to verify signed token: cms verification failure: crypto/rsa: verification error"
	_, err = Timestamp(ctx, req, opts)
	assertErrorEqual(expectedErr, err, t)
}

func assertErrorEqual(expected string, err error, t *testing.T) {
	if err == nil || expected != err.Error() {
		t.Fatalf("Expected error \"%v\" but was \"%v\"", expected, err)
	}
}
