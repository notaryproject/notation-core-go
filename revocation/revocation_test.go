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

package revocation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	revocationocsp "github.com/notaryproject/notation-core-go/revocation/ocsp"
	"github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/testhelper"
	"golang.org/x/crypto/ocsp"
)

func validateEquivalentCertResults(certResults, expectedCertResults []*result.CertRevocationResult, t *testing.T) {
	if len(certResults) != len(expectedCertResults) {
		t.Errorf("Length of certResults (%d) did not match expected length (%d)", len(certResults), len(expectedCertResults))
		return
	}
	for i, certResult := range certResults {
		if certResult.Result != expectedCertResults[i].Result {
			t.Errorf("Expected certResults[%d].Result to be %s, but got %s", i, expectedCertResults[i].Result, certResult.Result)
		}
		if len(certResult.ServerResults) != len(expectedCertResults[i].ServerResults) {
			t.Errorf("Length of certResults[%d].ServerResults (%d) did not match expected length (%d)", i, len(certResult.ServerResults), len(expectedCertResults[i].ServerResults))
			return
		}
		for j, serverResult := range certResult.ServerResults {
			if serverResult.Result != expectedCertResults[i].ServerResults[j].Result {
				t.Errorf("Expected certResults[%d].ServerResults[%d].Result to be %s, but got %s", i, j, expectedCertResults[i].ServerResults[j].Result, serverResult.Result)
			}
			if serverResult.Server != expectedCertResults[i].ServerResults[j].Server {
				t.Errorf("Expected certResults[%d].ServerResults[%d].Server to be %s, but got %s", i, j, expectedCertResults[i].ServerResults[j].Server, serverResult.Server)
			}
			if serverResult.Error == nil {
				if expectedCertResults[i].ServerResults[j].Error == nil {
					continue
				}
				t.Errorf("certResults[%d].ServerResults[%d].Error was nil, but expected %v", i, j, expectedCertResults[i].ServerResults[j].Error)
			} else if expectedCertResults[i].ServerResults[j].Error == nil {
				t.Errorf("Unexpected error for certResults[%d].ServerResults[%d].Error: %v", i, j, serverResult.Error)
			} else if serverResult.Error.Error() != expectedCertResults[i].ServerResults[j].Error.Error() {
				t.Errorf("Expected certResults[%d].ServerResults[%d].Error to be %v, but got %v", i, j, expectedCertResults[i].ServerResults[j].Error, serverResult.Error)
			}
		}

		if len(certResult.CRLResults) != len(expectedCertResults[i].CRLResults) {
			t.Errorf("Length of certResults[%d].CRLResults (%d) did not match expected length (%d)", i, len(certResult.CRLResults), len(expectedCertResults[i].CRLResults))
		}

		for j, crlResult := range certResult.CRLResults {
			if crlResult.ReasonCode != expectedCertResults[i].CRLResults[j].ReasonCode {
				t.Errorf("Expected certResults[%d].CRLResults[%d].ReasonCode to be %s, but got %s", i, j, expectedCertResults[i].CRLResults[j].ReasonCode, crlResult.ReasonCode)
			}

			resultErrorType := reflect.TypeOf(crlResult.Error)
			expectedErrorType := reflect.TypeOf(expectedCertResults[i].CRLResults[j].Error)
			if resultErrorType != expectedErrorType {
				t.Errorf("Expected certResults[%d].CRLResults[%d].Error to be of type %v, but got %v", i, j, expectedErrorType, resultErrorType)
			}

		}
	}
}

func getOKCertResult(server string) *result.CertRevocationResult {
	return &result.CertRevocationResult{
		Result: result.ResultOK,
		ServerResults: []*result.ServerResult{
			result.NewServerResult(result.ResultOK, server, nil),
		},
	}
}

func getOKCertResultForCRL() *result.CertRevocationResult {
	return &result.CertRevocationResult{
		Result:     result.ResultOK,
		CRLResults: []*result.CRLResult{},
	}
}

func getRootCertResult() *result.CertRevocationResult {
	return &result.CertRevocationResult{
		Result: result.ResultNonRevokable,
		ServerResults: []*result.ServerResult{
			result.NewServerResult(result.ResultNonRevokable, "", nil),
		},
	}
}

func TestNew(t *testing.T) {
	r, err := New(nil)
	expectedError := errors.New("invalid input: a non-nil httpClient must be specified")
	if r != nil && err.Error() != expectedError.Error() {
		t.Errorf("Expected New(nil) to fail with %v and %v, but received %v and %v", nil, expectedError, r, err)
	}

	client := http.DefaultClient
	r, err = New(client)
	if err != nil {
		t.Errorf("Expected to succeed with default client, but received error %v", err)
	}
	revR, ok := r.(*revocation)
	if !ok {
		t.Error("Expected New to create an object matching the internal revocation struct")
	} else if revR.ocspHTTPClient != client {
		t.Errorf("Expected New to set client to %v, but it was set to %v", client, revR.ocspHTTPClient)
	}
}

func TestNewTimestamp(t *testing.T) {
	expectedErrMsg := "invalid input: a non-nil httpClient must be specified"
	_, err := NewTimestamp(nil)
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}
}

func TestCheckRevocationStatusForSingleCert(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	revokableChain := []*x509.Certificate{revokableCertTuple.Cert, revokableIssuerTuple.Cert}
	testChain := []testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}

	t.Run("check non-revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{getOKCertResult(revokableChain[0].OCSPServer[0]), getRootCertResult()}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[0].OCSPServer[0], revocationocsp.UnknownStatusError{}),
				},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[0].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, &revokedTime, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
}

func TestCheckRevocationStatusForSelfSignedCert(t *testing.T) {
	selfSignedTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation revocation test self-signed cert")
	client := testhelper.MockClient([]testhelper.RSACertTuple{selfSignedTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	r, err := New(client)
	if err != nil {
		t.Errorf("Expected successful creation of revocation, but received error: %v", err)
	}
	certResults, err := r.Validate([]*x509.Certificate{selfSignedTuple.Cert}, time.Now())
	if err != nil {
		t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
	}
	expectedCertResults := []*result.CertRevocationResult{getRootCertResult()}
	validateEquivalentCertResults(certResults, expectedCertResults, t)
}

func TestCheckRevocationStatusForRootCert(t *testing.T) {
	rootTuple := testhelper.GetRSARootCertificate()
	client := testhelper.MockClient([]testhelper.RSACertTuple{rootTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	r, err := New(client)
	if err != nil {
		t.Errorf("Expected successful creation of revocation, but received error: %v", err)
	}

	certResults, err := r.Validate([]*x509.Certificate{rootTuple.Cert}, time.Now())
	expectedErr := result.InvalidChainError{Err: errors.New("invalid self-signed certificate. Error: certificate with subject \"CN=Notation Test RSA Root,O=Notary,L=Seattle,ST=WA,C=US\": if the basic constraints extension is present, the ca field must be set to false")}
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected Validate to fail with %v, but got: %v", expectedErr, err)
	}
	if certResults != nil {
		t.Error("Expected certResults to be nil when there is an error")
	}
}

func TestCheckRevocationStatusForChain(t *testing.T) {
	zeroTime := time.Time{}
	testChain := testhelper.GetRevokableRSAChain(6, true, false)
	revokableChain := make([]*x509.Certificate, 6)
	for i, tuple := range testChain {
		revokableChain[i] = tuple.Cert
		revokableChain[i].NotBefore = zeroTime
	}

	t.Run("empty chain", func(t *testing.T) {
		r, err := New(&http.Client{Timeout: 5 * time.Second})
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate([]*x509.Certificate{}, time.Now())
		expectedErr := result.InvalidChainError{Err: errors.New("chain does not contain any certificates")}
		if err == nil || err.Error() != expectedErr.Error() {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", expectedErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})
	t.Run("check non-revoked chain", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			getOKCertResult(revokableChain[2].OCSPServer[0]),
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check chain with 1 Unknown cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], revocationocsp.UnknownStatusError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 unknown and 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], revocationocsp.UnknownStatusError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[4].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be future revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			getOKCertResult(revokableChain[2].OCSPServer[0]),
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 unknown and 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be unknown, 5th will be future revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], revocationocsp.UnknownStatusError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 revoked cert before signing time", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now().Add(time.Hour))
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 revoked cert after zero signing time", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be revoked, the rest will be good

		if !zeroTime.IsZero() {
			t.Errorf("exected zeroTime.IsZero() to be true")
		}

		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(revokableChain, time.Now().Add(time.Hour))
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
}

func TestCheckRevocationStatusForTimestampChain(t *testing.T) {
	zeroTime := time.Time{}
	testChain := testhelper.GetRevokableRSATimestampChain(6)
	revokableChain := make([]*x509.Certificate, 6)
	for i, tuple := range testChain {
		revokableChain[i] = tuple.Cert
		revokableChain[i].NotBefore = zeroTime
	}

	t.Run("invalid revocation purpose", func(t *testing.T) {
		revocationClient := &revocation{
			ctx:              context.Background(),
			ocspHTTPClient:   &http.Client{Timeout: 5 * time.Second},
			certChainPurpose: -1,
		}

		_, err := revocationClient.Validate(revokableChain, time.Now())
		if err == nil {
			t.Error("Expected Validate to fail with an error, but it succeeded")
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		r, err := NewTimestamp(&http.Client{Timeout: 5 * time.Second})
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate([]*x509.Certificate{}, time.Now())
		expectedErr := result.InvalidChainError{Err: errors.New("chain does not contain any certificates")}
		if err == nil || err.Error() != expectedErr.Error() {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", expectedErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("invalid timestamping chain", func(t *testing.T) {
		r, err := NewTimestamp(&http.Client{Timeout: 5 * time.Second})
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certChain := testhelper.GetRevokableRSATimestampChain(3)

		_, err = r.Validate([]*x509.Certificate{certChain[0].Cert, certChain[1].Cert}, time.Now())
		if err == nil {
			t.Errorf("Expected CheckStatus to fail, but got nil")
		}
	})

	t.Run("check non-revoked chain", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := NewTimestamp(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			getOKCertResult(revokableChain[2].OCSPServer[0]),
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check chain with 1 Unknown cert", func(t *testing.T) {
		// 3rd cert will be unknown, the rest will be good
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good}, nil, true)
		r, err := NewTimestamp(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], revocationocsp.UnknownStatusError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 revoked cert", func(t *testing.T) {
		// 3rd cert will be revoked, the rest will be good
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		r, err := NewTimestamp(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 unknown and 1 revoked cert", func(t *testing.T) {
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		r, err := NewTimestamp(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], revocationocsp.UnknownStatusError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[4].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		// 3rd cert will be future revoked, the rest will be good
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		r, err := NewTimestamp(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			getOKCertResult(revokableChain[2].OCSPServer[0]),
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 unknown and 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		// 3rd cert will be unknown, 5th will be future revoked, the rest will be good
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		r, err := NewTimestamp(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(revokableChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], revocationocsp.UnknownStatusError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 revoked cert before signing time", func(t *testing.T) {
		// 3rd cert will be revoked, the rest will be good
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		r, err := NewTimestamp(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(revokableChain, time.Now().Add(time.Hour))
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 revoked cert after zero signing time", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		// 3rd cert will be revoked, the rest will be good
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		if !zeroTime.IsZero() {
			t.Errorf("exected zeroTime.IsZero() to be true")
		}
		r, err := NewTimestamp(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(revokableChain, time.Now().Add(time.Hour))
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], revocationocsp.RevokedError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
}

func TestCheckRevocationErrors(t *testing.T) {
	leafCertTuple := testhelper.GetRSALeafCertificate()
	rootCertTuple := testhelper.GetRSARootCertificate()
	noOCSPChain := []*x509.Certificate{leafCertTuple.Cert, rootCertTuple.Cert}

	revokableTuples := testhelper.GetRevokableRSAChain(3, true, false)
	noRootChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert}
	backwardsChain := []*x509.Certificate{revokableTuples[2].Cert, revokableTuples[1].Cert, revokableTuples[0].Cert}
	okChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert, revokableTuples[2].Cert}

	expiredLeaf, _ := x509.ParseCertificate(revokableTuples[0].Cert.Raw)
	expiredLeaf.IsCA = false
	expiredLeaf.KeyUsage = x509.KeyUsageDigitalSignature
	expiredLeaf.OCSPServer = []string{"http://example.com/expired_ocsp"}
	expiredChain := []*x509.Certificate{expiredLeaf, revokableTuples[1].Cert, revokableTuples[2].Cert}

	noHTTPLeaf, _ := x509.ParseCertificate(revokableTuples[0].Cert.Raw)
	noHTTPLeaf.IsCA = false
	noHTTPLeaf.KeyUsage = x509.KeyUsageDigitalSignature
	noHTTPLeaf.OCSPServer = []string{"ldap://ds.example.com:123/chain_ocsp/0"}
	noHTTPChain := []*x509.Certificate{noHTTPLeaf, revokableTuples[1].Cert, revokableTuples[2].Cert}

	backwardsChainErr := result.InvalidChainError{Err: errors.New("leaf certificate with subject \"CN=Notation Test Revokable RSA Chain Cert Root,O=Notary,L=Seattle,ST=WA,C=US\" is self-signed. Certificate chain must not contain self-signed leaf certificate")}
	chainRootErr := result.InvalidChainError{Err: errors.New("root certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\" is not self-signed. Certificate chain must end with a valid self-signed root certificate")}
	expiredRespErr := revocationocsp.GenericError{Err: errors.New("expired OCSP response")}
	noHTTPErr := revocationocsp.GenericError{Err: errors.New("OCSPServer protocol ldap is not supported")}

	r, err := New(&http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Errorf("Expected successful creation of revocation, but received error: %v", err)
	}

	t.Run("no OCSPServer specified", func(t *testing.T) {
		certResults, err := r.Validate(noOCSPChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultNonRevokable,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultNonRevokable, "", nil),
				},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("chain missing root", func(t *testing.T) {
		certResults, err := r.Validate(noRootChain, time.Now())
		if err == nil || err.Error() != chainRootErr.Error() {
			t.Errorf("Expected Validate to fail with %v, but got: %v", chainRootErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("backwards chain", func(t *testing.T) {
		certResults, err := r.Validate(backwardsChain, time.Now())
		if err == nil || err.Error() != backwardsChainErr.Error() {
			t.Errorf("Expected Validate to fail with %v, but got: %v", backwardsChainErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		timeoutClient := &http.Client{Timeout: 1 * time.Nanosecond}
		timeoutR, err := New(timeoutClient)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := timeoutR.Validate(okChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, okChain[0].OCSPServer[0], revocationocsp.TimeoutError{}),
				},
			},
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, okChain[1].OCSPServer[0], revocationocsp.TimeoutError{}),
				},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("expired ocsp response", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		expiredR, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := expiredR.Validate(expiredChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, expiredChain[0].OCSPServer[0], expiredRespErr),
				},
			},
			getOKCertResult(expiredChain[1].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("OCSP pkixNoCheck missing", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, false)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(okChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(okChain[0].OCSPServer[0]),
			getOKCertResult(okChain[1].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("non-HTTP URI error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		certResults, err := r.Validate(noHTTPChain, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, noHTTPChain[0].OCSPServer[0], noHTTPErr),
				},
			},
			getOKCertResult(noHTTPChain[1].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
}

func TestCheckRevocationInvalidChain(t *testing.T) {
	revokableTuples := testhelper.GetRevokableRSAChain(4, true, false)
	misorderedIntermediateTuples := []testhelper.RSACertTuple{revokableTuples[1], revokableTuples[0], revokableTuples[2], revokableTuples[3]}
	misorderedIntermediateChain := []*x509.Certificate{revokableTuples[1].Cert, revokableTuples[0].Cert, revokableTuples[2].Cert, revokableTuples[3].Cert}
	for i, cert := range misorderedIntermediateChain {
		if i != (len(misorderedIntermediateChain) - 1) {
			// Skip root which won't have an OCSP Server
			cert.OCSPServer[0] = fmt.Sprintf("http://example.com/chain_ocsp/%d", i)
		}
	}

	missingIntermediateChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[2].Cert, revokableTuples[3].Cert}
	for i, cert := range missingIntermediateChain {
		if i != (len(missingIntermediateChain) - 1) {
			// Skip root which won't have an OCSP Server
			cert.OCSPServer[0] = fmt.Sprintf("http://example.com/chain_ocsp/%d", i)
		}
	}

	missingIntermediateErr := result.InvalidChainError{Err: errors.New("certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 4,O=Notary,L=Seattle,ST=WA,C=US\" is not issued by \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\"")}
	misorderedChainErr := result.InvalidChainError{Err: errors.New("invalid certificates or certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 3,O=Notary,L=Seattle,ST=WA,C=US\" is not issued by \"CN=Notation Test Revokable RSA Chain Cert 4,O=Notary,L=Seattle,ST=WA,C=US\". Error: x509: invalid signature: parent certificate cannot sign this kind of certificate")}

	t.Run("chain missing intermediate", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(missingIntermediateChain, time.Now())
		if err == nil || err.Error() != missingIntermediateErr.Error() {
			t.Errorf("Expected Validate to fail with %v, but got: %v", missingIntermediateErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("chain out of order", func(t *testing.T) {
		client := testhelper.MockClient(misorderedIntermediateTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := r.Validate(misorderedIntermediateChain, time.Now())
		if err == nil || err.Error() != misorderedChainErr.Error() {
			t.Errorf("Expected Validate to fail with %v, but got: %v", misorderedChainErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})
}

func TestCRL(t *testing.T) {
	t.Run("CRL check valid", func(t *testing.T) {
		chain := testhelper.GetRevokableRSAChain(3, false, true)

		revocationClient, err := NewWithOptions(context.Background(), &Options{
			CRLHTTPClient: &http.Client{
				Timeout: 5 * time.Second,
				Transport: &crlRoundTripper{
					CertChain: chain,
					Revoked:   false,
				},
			},
			OCSPHTTPClient: &http.Client{},
		})
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := revocationClient.Validate([]*x509.Certificate{
			chain[0].Cert, // leaf
			chain[1].Cert, // intermediate
			chain[2].Cert, // root
		}, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}

		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResultForCRL(),
			getOKCertResultForCRL(),
			getRootCertResult(),
		}

		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("CRL check with revoked status", func(t *testing.T) {
		chain := testhelper.GetRevokableRSAChain(3, false, true)

		revocationClient, err := NewWithOptions(context.Background(), &Options{
			CRLHTTPClient: &http.Client{
				Timeout: 5 * time.Second,
				Transport: &crlRoundTripper{
					CertChain: chain,
					Revoked:   true,
				},
			},
			OCSPHTTPClient: &http.Client{},
		})
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := revocationClient.Validate([]*x509.Certificate{
			chain[0].Cert, // leaf
			chain[1].Cert, // intermediate
			chain[2].Cert, // root
		}, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}

		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultRevoked,
				CRLResults: []*result.CRLResult{
					{
						ReasonCode: result.CRLReasonCodeKeyCompromise,
					},
				},
			},
			{
				Result: result.ResultRevoked,
				CRLResults: []*result.CRLResult{
					{
						ReasonCode: result.CRLReasonCodeKeyCompromise,
					},
				},
			},
			getRootCertResult(),
		}

		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("OCSP fallback to CRL", func(t *testing.T) {
		chain := testhelper.GetRevokableRSAChain(3, true, true)

		revocationClient, err := NewWithOptions(context.Background(), &Options{
			CRLHTTPClient: &http.Client{
				Timeout: 5 * time.Second,
				Transport: &crlRoundTripper{
					CertChain: chain,
					Revoked:   true,
					FailOCSP:  true,
				},
			},
			OCSPHTTPClient: &http.Client{},
		})
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		certResults, err := revocationClient.Validate([]*x509.Certificate{
			chain[0].Cert, // leaf
			chain[1].Cert, // intermediate
			chain[2].Cert, // root
		}, time.Now())
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}

		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultRevoked,
				CRLResults: []*result.CRLResult{
					{
						ReasonCode: result.CRLReasonCodeKeyCompromise,
					},
				},
				Error: result.OCSPFallbackError{},
			},
			{
				Result: result.ResultRevoked,
				CRLResults: []*result.CRLResult{
					{
						ReasonCode: result.CRLReasonCodeKeyCompromise,
					},
				},
				Error: result.OCSPFallbackError{},
			},
			getRootCertResult(),
		}

		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
}

func TestNewWithOptions(t *testing.T) {
	t.Run("nil ctx", func(t *testing.T) {
		var ctx context.Context = nil
		_, err := NewWithOptions(ctx, &Options{})
		if err == nil {
			t.Error("Expected NewWithOptions to fail with an error, but it succeeded")
		}
	})

	t.Run("nil OCSP HTTP Client", func(t *testing.T) {
		_, err := NewWithOptions(context.Background(), &Options{})
		if err == nil {
			t.Error("Expected NewWithOptions to fail with an error, but it succeeded")
		}
	})

	t.Run("nil CRL HTTP Client", func(t *testing.T) {
		_, err := NewWithOptions(context.Background(), &Options{
			OCSPHTTPClient: &http.Client{},
		})
		if err == nil {
			t.Error("Expected NewWithOptions to fail with an error, but it succeeded")
		}
	})

	t.Run("invalid CertChainPurpose", func(t *testing.T) {
		_, err := NewWithOptions(context.Background(), &Options{
			OCSPHTTPClient:   &http.Client{},
			CRLHTTPClient:    &http.Client{},
			CertChainPurpose: -1,
		})
		if err == nil {
			t.Error("Expected NewWithOptions to fail with an error, but it succeeded")
		}
	})

}

type crlRoundTripper struct {
	CertChain []testhelper.RSACertTuple
	Revoked   bool
	FailOCSP  bool
}

func (rt *crlRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// e.g. ocsp URL: http://example.com/chain_ocsp/0
	// e.g. crl URL: http://example.com/chain_crl/0
	parts := strings.Split(req.URL.Path, "/")

	isOCSP := parts[len(parts)-2] == "chain_ocsp"
	// fail OCSP
	if rt.FailOCSP && isOCSP {
		return nil, errors.New("OCSP failed")
	}

	// choose the cert suffix based on suffix of request url
	// e.g. http://example.com/chain_crl/0 -> 0
	i, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return nil, err
	}
	if i >= len(rt.CertChain) {
		return nil, errors.New("invalid index")
	}

	cert := rt.CertChain[i].Cert
	crl := &x509.RevocationList{
		NextUpdate: time.Now().Add(time.Hour),
		Number:     big.NewInt(20240720),
	}

	if rt.Revoked {
		crl.RevokedCertificateEntries = []x509.RevocationListEntry{
			{
				SerialNumber:   cert.SerialNumber,
				RevocationTime: time.Now().Add(-time.Hour),
				ReasonCode:     int(result.CRLReasonCodeKeyCompromise),
			},
		}
	}

	issuerCert := rt.CertChain[i+1].Cert
	issuerKey := rt.CertChain[i+1].PrivateKey
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crl, issuerCert, issuerKey)
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(crlBytes)),
	}, nil
}
