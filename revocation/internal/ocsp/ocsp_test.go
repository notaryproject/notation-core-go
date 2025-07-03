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

package ocsp

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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

func TestCheckStatus(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	ocspServer := revokableCertTuple.Cert.OCSPServer[0]
	revokableChain := []*x509.Certificate{revokableCertTuple.Cert, revokableIssuerTuple.Cert}
	testChain := []testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}
	ctx := context.Background()

	t.Run("check non-revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := CertCheckStatusOptions{
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := CertCheckStatus(ctx, revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*result.CertRevocationResult{getOKCertResult(ocspServer)}
		validateEquivalentCertResults([]*result.CertRevocationResult{certResult}, expectedCertResults, t)
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		opts := CertCheckStatusOptions{
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := CertCheckStatus(ctx, revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*result.CertRevocationResult{{
			Result: result.ResultUnknown,
			ServerResults: []*result.ServerResult{
				result.NewServerResult(result.ResultUnknown, ocspServer, UnknownStatusError{}),
			},
		}}
		validateEquivalentCertResults([]*result.CertRevocationResult{certResult}, expectedCertResults, t)
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, nil, true)
		opts := CertCheckStatusOptions{
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := CertCheckStatus(ctx, revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*result.CertRevocationResult{{
			Result: result.ResultRevoked,
			ServerResults: []*result.ServerResult{
				result.NewServerResult(result.ResultRevoked, ocspServer, RevokedError{}),
			},
		}}
		validateEquivalentCertResults([]*result.CertRevocationResult{certResult}, expectedCertResults, t)
	})
	t.Run("check OCSP future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, &revokedTime, true)
		opts := CertCheckStatusOptions{
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := CertCheckStatus(ctx, revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*result.CertRevocationResult{getOKCertResult(ocspServer)}
		validateEquivalentCertResults([]*result.CertRevocationResult{certResult}, expectedCertResults, t)
	})

	t.Run("certificate doesn't support OCSP", func(t *testing.T) {
		ocspResult := CertCheckStatus(ctx, &x509.Certificate{}, revokableIssuerTuple.Cert, CertCheckStatusOptions{})
		expectedResult := &result.CertRevocationResult{
			Result:        result.ResultNonRevokable,
			ServerResults: []*result.ServerResult{toServerResult("", NoServerError{})},
		}

		validateEquivalentCertResults([]*result.CertRevocationResult{ocspResult}, []*result.CertRevocationResult{expectedResult}, t)
	})
}

func TestCheckStatusFromServer(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	ctx := context.Background()

	t.Run("server url is not http", func(t *testing.T) {
		server := "https://localhost.test"
		serverResult := checkStatusFromServer(ctx, revokableCertTuple.Cert, revokableIssuerTuple.Cert, server, CertCheckStatusOptions{})
		expectedResult := toServerResult(server, GenericError{Err: fmt.Errorf("OCSPServer protocol %s is not supported", "https")})
		if serverResult.Result != expectedResult.Result {
			t.Errorf("Expected Result to be %s, but got %s", expectedResult.Result, serverResult.Result)
		}
		if serverResult.Server != expectedResult.Server {
			t.Errorf("Expected Server to be %s, but got %s", expectedResult.Server, serverResult.Server)
		}
		if serverResult.Error == nil {
			t.Errorf("Expected Error to be %v, but got nil", expectedResult.Error)
		} else if serverResult.Error.Error() != expectedResult.Error.Error() {
			t.Errorf("Expected Error to be %v, but got %v", expectedResult.Error, serverResult.Error)
		}
	})

	t.Run("request error", func(t *testing.T) {
		server := "http://localhost.test"
		serverResult := checkStatusFromServer(ctx, revokableCertTuple.Cert, revokableIssuerTuple.Cert, server, CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Transport: &failedTransport{},
			},
		})
		errorMessage := "failed to execute request"
		if !strings.Contains(serverResult.Error.Error(), errorMessage) {
			t.Errorf("Expected Error to contain %v, but got %v", errorMessage, serverResult.Error)
		}
	})

	t.Run("ocsp expired", func(t *testing.T) {
		client := testhelper.MockClient([]testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		server := "http://localhost.test/expired_ocsp"
		serverResult := checkStatusFromServer(ctx, revokableCertTuple.Cert, revokableIssuerTuple.Cert, server, CertCheckStatusOptions{
			HTTPClient: client,
		})
		errorMessage := "expired OCSP response"
		if !strings.Contains(serverResult.Error.Error(), errorMessage) {
			t.Errorf("Expected Error to contain %v, but got %v", errorMessage, serverResult.Error)
		}
	})

	t.Run("ocsp request roundtrip failed", func(t *testing.T) {
		client := testhelper.MockClient([]testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		server := "http://localhost.test"
		//lint:ignore SA1012 nil context is used for testing
		serverResult := checkStatusFromServer(nil, revokableCertTuple.Cert, revokableIssuerTuple.Cert, server, CertCheckStatusOptions{
			HTTPClient: client,
		})
		errorMessage := "net/http: nil Context"
		if !strings.Contains(serverResult.Error.Error(), errorMessage) {
			t.Errorf("Expected Error to contain %v, but got %v", errorMessage, serverResult.Error)
		}
	})

	t.Run("ocsp request roundtrip timeout", func(t *testing.T) {
		server := "http://localhost.test"
		serverResult := checkStatusFromServer(ctx, revokableCertTuple.Cert, revokableIssuerTuple.Cert, server, CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Timeout: 1 * time.Second,
				Transport: &failedTransport{
					timeout: true,
				},
			},
		})
		errorMessage := "exceeded timeout threshold of 1.00 seconds for OCSP check"
		if !strings.Contains(serverResult.Error.Error(), errorMessage) {
			t.Errorf("Expected Error to contain %v, but got %v", errorMessage, serverResult.Error)
		}
	})
}

func TestPostRequest(t *testing.T) {
	t.Run("failed to generate request", func(t *testing.T) {
		//lint:ignore SA1012 nil context is used for testing
		_, err := postRequest(nil, nil, "http://localhost.test", &http.Client{
			Transport: &failedTransport{},
		})
		expectedErrMsg := "net/http: nil Context"
		if err == nil || err.Error() != expectedErrMsg {
			t.Errorf("Expected error %s, but got %s", expectedErrMsg, err)
		}
	})

	t.Run("failed to execute request", func(t *testing.T) {
		_, err := postRequest(context.Background(), nil, "http://localhost.test", &http.Client{
			Transport: &failedTransport{},
		})
		expectedErrMsg := "Post \"http://localhost.test\": failed to execute request"
		if err == nil || err.Error() != expectedErrMsg {
			t.Errorf("Expected error %s, but got %s", expectedErrMsg, err)
		}
	})
}

func TestExecuteOCSPCheck(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	ctx := context.Background()

	t.Run("http response status is not 200", func(t *testing.T) {
		_, err := executeOCSPCheck(ctx, revokableCertTuple.Cert, revokableIssuerTuple.Cert, "localhost.test", CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Transport: &failedTransport{
					statusCode: http.StatusNotFound,
				},
			},
		})
		expectedErrMsg := "failed to retrieve OCSP: response had status code 404"
		if err == nil || err.Error() != expectedErrMsg {
			t.Errorf("Expected error %s, but got %s", expectedErrMsg, err)
		}
	})
}

type testTimeoutError struct{}

func (e testTimeoutError) Error() string {
	return "test timeout"
}

func (e testTimeoutError) Timeout() bool {
	return true
}

type failedTransport struct {
	timeout    bool
	statusCode int
}

func (f *failedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if f.timeout {
		return nil, &url.Error{
			Err: testTimeoutError{},
		}
	}

	if f.statusCode != 0 {
		return &http.Response{
			StatusCode: f.statusCode,
		}, nil
	}

	return nil, fmt.Errorf("failed to execute request")
}
