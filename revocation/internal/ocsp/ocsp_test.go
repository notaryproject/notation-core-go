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
	"crypto/x509"
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

	t.Run("check non-revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := CertCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*result.CertRevocationResult{getOKCertResult(ocspServer)}
		validateEquivalentCertResults([]*result.CertRevocationResult{certResult}, expectedCertResults, t)
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		opts := Options{
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := CertCheckStatus(revokableChain[0], revokableChain[1], opts)
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
		opts := Options{
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := CertCheckStatus(revokableChain[0], revokableChain[1], opts)
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
		opts := Options{
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := CertCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*result.CertRevocationResult{getOKCertResult(ocspServer)}
		validateEquivalentCertResults([]*result.CertRevocationResult{certResult}, expectedCertResults, t)
	})
}
