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
	"errors"
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
	rootCerts, err := nx509.ReadCertificateFile("testdata/tsaRootCert.crt")
	if err != nil || len(rootCerts) == 0 {
		t.Fatal("failed to read root CA certificate:", err)
	}
	rootCert := rootCerts[0]
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCert)

	// --------------- Success case ----------------------------------
	timestamper, err := tspclient.NewHTTPTimestamper(nil, rfc3161TSAurl)
	if err != nil {
		t.Fatal(err)
	}
	req := &signature.SignRequest{
		Timestamper: timestamper,
		TSARootCAs:  rootCAs,
	}
	opts := tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
	}
	_, err = Timestamp(req, opts)
	if err != nil {
		t.Fatal(err)
	}

	// ------------- Failure cases ------------------------
	opts = tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA1,
	}
	expectedErr := "malformed timestamping request: unsupported hashing algorithm: SHA-1"
	_, err = Timestamp(req, opts)
	assertErrorEqual(expectedErr, err, t)

	req = &signature.SignRequest{
		Timestamper: dummyTimestamper{},
		TSARootCAs:  rootCAs,
	}
	opts = tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		NoNonce:       true,
	}
	expectedErr = "failed to timestamp"
	_, err = Timestamp(req, opts)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Fatalf("expected error message to contain %s, but got %v", expectedErr, err)
	}

	req = &signature.SignRequest{
		Timestamper: dummyTimestamper{
			respWithRejectedStatus: true,
		},
		TSARootCAs: rootCAs,
	}
	expectedErr = "invalid timestamping response: invalid response with status code 2: rejected"
	_, err = Timestamp(req, opts)
	assertErrorEqual(expectedErr, err, t)

	req = &signature.SignRequest{
		Timestamper: dummyTimestamper{
			invalidTSTInfo: true,
		},
		TSARootCAs: rootCAs,
	}
	expectedErr = "cannot unmarshal TSTInfo from timestamp token: asn1: structure error: tags don't match (23 vs {class:0 tag:16 length:3 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:24 set:false omitEmpty:false} Time @89"
	_, err = Timestamp(req, opts)
	assertErrorEqual(expectedErr, err, t)

	opts = tspclient.RequestOptions{
		Content:       []byte("mismatch"),
		HashAlgorithm: crypto.SHA256,
		NoNonce:       true,
	}
	req = &signature.SignRequest{
		Timestamper: dummyTimestamper{
			failValidate: true,
		},
		TSARootCAs: rootCAs,
	}
	expectedErr = "invalid TSTInfo: mismatched message"
	_, err = Timestamp(req, opts)
	assertErrorEqual(expectedErr, err, t)

	opts = tspclient.RequestOptions{
		Content:       []byte("notation"),
		HashAlgorithm: crypto.SHA256,
		NoNonce:       true,
	}
	req = &signature.SignRequest{
		Timestamper: dummyTimestamper{
			invalidSignature: true,
		},
		TSARootCAs: rootCAs,
	}
	expectedErr = "failed to verify signed token: cms verification failure: crypto/rsa: verification error"
	_, err = Timestamp(req, opts)
	assertErrorEqual(expectedErr, err, t)
}

func assertErrorEqual(expected string, err error, t *testing.T) {
	if err == nil || expected != err.Error() {
		t.Fatalf("Expected error \"%v\" but was \"%v\"", expected, err)
	}
}

type dummyTimestamper struct {
	respWithRejectedStatus bool
	invalidTSTInfo         bool
	failValidate           bool
	invalidSignature       bool
}

func (d dummyTimestamper) Timestamp(context.Context, *tspclient.Request) (*tspclient.Response, error) {
	if d.respWithRejectedStatus {
		return &tspclient.Response{
			Status: pki.StatusInfo{
				Status: pki.StatusRejection,
			},
		}, nil
	}
	if d.invalidTSTInfo {
		token, err := os.ReadFile("testdata/TimeStampTokenWithInvalidTSTInfo.p7s")
		if err != nil {
			return nil, err
		}
		return &tspclient.Response{
			Status: pki.StatusInfo{
				Status: pki.StatusGranted,
			},
			TimestampToken: asn1.RawValue{
				FullBytes: token,
			},
		}, nil
	}
	if d.failValidate {
		token, err := os.ReadFile("testdata/TimeStampToken.p7s")
		if err != nil {
			return nil, err
		}
		return &tspclient.Response{
			Status: pki.StatusInfo{
				Status: pki.StatusGranted,
			},
			TimestampToken: asn1.RawValue{
				FullBytes: token,
			},
		}, nil
	}
	if d.invalidSignature {
		token, err := os.ReadFile("testdata/TimeStampTokenWithInvalidSignature.p7s")
		if err != nil {
			return nil, err
		}
		return &tspclient.Response{
			Status: pki.StatusInfo{
				Status: pki.StatusGranted,
			},
			TimestampToken: asn1.RawValue{
				FullBytes: token,
			},
		}, nil
	}
	return nil, errors.New("failed to timestamp")
}
