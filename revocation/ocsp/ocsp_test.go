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
	"errors"
	"fmt"
	"net/http"
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

func getRootCertResult() *result.CertRevocationResult {
	return &result.CertRevocationResult{
		Result: result.ResultNonRevokable,
		ServerResults: []*result.ServerResult{
			result.NewServerResult(result.ResultNonRevokable, "", nil),
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
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResult := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*result.CertRevocationResult{getOKCertResult(ocspServer)}
		validateEquivalentCertResults([]*result.CertRevocationResult{certResult}, expectedCertResults, t)
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResult := certCheckStatus(revokableChain[0], revokableChain[1], opts)
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
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResult := certCheckStatus(revokableChain[0], revokableChain[1], opts)
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
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResult := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*result.CertRevocationResult{getOKCertResult(ocspServer)}
		validateEquivalentCertResults([]*result.CertRevocationResult{certResult}, expectedCertResults, t)
	})
}

func TestCheckStatusForSelfSignedCert(t *testing.T) {
	selfSignedTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation revocation test self-signed cert")
	client := testhelper.MockClient([]testhelper.RSACertTuple{selfSignedTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	opts := Options{
		CertChain:        []*x509.Certificate{selfSignedTuple.Cert},
		CertChainPurpose: x509.ExtKeyUsageCodeSigning,
		SigningTime:      time.Now(),
		HTTPClient:       client,
	}

	certResults, err := CheckStatus(opts)
	if err != nil {
		t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
	}
	expectedCertResults := []*result.CertRevocationResult{getRootCertResult()}
	validateEquivalentCertResults(certResults, expectedCertResults, t)
}

func TestCheckStatusForRootCert(t *testing.T) {
	rootTuple := testhelper.GetRSARootCertificate()
	client := testhelper.MockClient([]testhelper.RSACertTuple{rootTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	opts := Options{
		CertChain:        []*x509.Certificate{rootTuple.Cert},
		CertChainPurpose: x509.ExtKeyUsageCodeSigning,
		SigningTime:      time.Now(),
		HTTPClient:       client,
	}

	certResults, err := CheckStatus(opts)
	expectedErr := result.InvalidChainError{Err: errors.New("invalid self-signed certificate. Error: certificate with subject \"CN=Notation Test RSA Root,O=Notary,L=Seattle,ST=WA,C=US\": if the basic constraints extension is present, the ca field must be set to false")}
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected CheckStatus to fail with %v, but got: %v", expectedErr, err)
	}
	if certResults != nil {
		t.Error("Expected certResults to be nil when there is an error")
	}
}

func TestCheckStatusForNonSelfSignedSingleCert(t *testing.T) {
	certTuple := testhelper.GetRSALeafCertificate()
	client := testhelper.MockClient([]testhelper.RSACertTuple{certTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	opts := Options{
		CertChain:        []*x509.Certificate{certTuple.Cert},
		CertChainPurpose: x509.ExtKeyUsageCodeSigning,
		SigningTime:      time.Now(),
		HTTPClient:       client,
	}

	certResults, err := CheckStatus(opts)
	expectedErr := result.InvalidChainError{Err: errors.New("invalid self-signed certificate. subject: \"CN=Notation Test RSA Leaf Cert,O=Notary,L=Seattle,ST=WA,C=US\". Error: crypto/rsa: verification error")}
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected CheckStatus to fail with %v, but got: %v", expectedErr, err)
	}
	if certResults != nil {
		t.Error("Expected certResults to be nil when there is an error")
	}
}

func TestCheckStatusForChain(t *testing.T) {
	zeroTime := time.Time{}
	testChain := testhelper.GetRevokableRSAChain(6)
	revokableChain := make([]*x509.Certificate, 6)
	for i, tuple := range testChain {
		revokableChain[i] = tuple.Cert
		revokableChain[i].NotBefore = zeroTime
	}

	t.Run("empty chain", func(t *testing.T) {
		opts := Options{
			CertChain:        []*x509.Certificate{},
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
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
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResults, err := CheckStatus(opts)
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
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], UnknownStatusError{}),
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
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], RevokedError{}),
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
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], UnknownStatusError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[4].OCSPServer[0], RevokedError{}),
				},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be revoked, the rest will be good
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResults, err := CheckStatus(opts)
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
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, revokableChain[2].OCSPServer[0], UnknownStatusError{}),
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
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now().Add(time.Hour),
			HTTPClient:       client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], RevokedError{}),
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
		opts := Options{
			CertChain:        revokableChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      zeroTime,
			HTTPClient:       client,
		}

		if !zeroTime.IsZero() {
			t.Errorf("exected zeroTime.IsZero() to be true")
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			getOKCertResult(revokableChain[0].OCSPServer[0]),
			getOKCertResult(revokableChain[1].OCSPServer[0]),
			{
				Result: result.ResultRevoked,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultRevoked, revokableChain[2].OCSPServer[0], RevokedError{}),
				},
			},
			getOKCertResult(revokableChain[3].OCSPServer[0]),
			getOKCertResult(revokableChain[4].OCSPServer[0]),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
}

func TestCheckStatusErrors(t *testing.T) {
	leafCertTuple := testhelper.GetRSALeafCertificate()
	rootCertTuple := testhelper.GetRSARootCertificate()
	noOCSPChain := []*x509.Certificate{leafCertTuple.Cert, rootCertTuple.Cert}

	revokableTuples := testhelper.GetRevokableRSAChain(3)
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

	timestampSigningCertErr := result.InvalidChainError{Err: errors.New("timestamp signing certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 3,O=Notary,L=Seattle,ST=WA,C=US\" must have and only have Timestamping as extended key usage")}
	backwardsChainErr := result.InvalidChainError{Err: errors.New("leaf certificate with subject \"CN=Notation Test Revokable RSA Chain Cert Root,O=Notary,L=Seattle,ST=WA,C=US\" is self-signed. Certificate chain must not contain self-signed leaf certificate")}
	chainRootErr := result.InvalidChainError{Err: errors.New("root certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\" is not self-signed. Certificate chain must end with a valid self-signed root certificate")}
	expiredRespErr := GenericError{Err: errors.New("expired OCSP response")}
	noHTTPErr := GenericError{Err: errors.New("OCSPServer protocol ldap is not supported")}

	t.Run("no OCSPServer specified", func(t *testing.T) {
		opts := Options{
			CertChain:        noOCSPChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
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
		opts := Options{
			CertChain:        noRootChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
		if err == nil || err.Error() != chainRootErr.Error() {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", chainRootErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("backwards chain", func(t *testing.T) {
		opts := Options{
			CertChain:        backwardsChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
		if err == nil || err.Error() != backwardsChainErr.Error() {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", backwardsChainErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("check codesigning cert with PurposeTimestamping", func(t *testing.T) {
		opts := Options{
			CertChain:        okChain,
			CertChainPurpose: x509.ExtKeyUsageTimeStamping,
			SigningTime:      time.Now(),
			HTTPClient:       http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
		if err == nil || err.Error() != timestampSigningCertErr.Error() {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", timestampSigningCertErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("check with default CertChainPurpose", func(t *testing.T) {
		opts := Options{
			CertChain:   okChain,
			SigningTime: time.Now(),
			HTTPClient:  http.DefaultClient,
		}
		_, err := CheckStatus(opts)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("check with unknwon CertChainPurpose", func(t *testing.T) {
		opts := Options{
			CertChain:        okChain,
			CertChainPurpose: -1,
			SigningTime:      time.Now(),
			HTTPClient:       http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
		if err == nil || err.Error() != "invalid chain: expected chain to be correct and complete: unknown certificate chain purpose -1" {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", timestampSigningCertErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		timeoutClient := &http.Client{Timeout: 1 * time.Nanosecond}
		opts := Options{
			CertChain:        okChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       timeoutClient,
		}
		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*result.CertRevocationResult{
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, okChain[0].OCSPServer[0], TimeoutError{}),
				},
			},
			{
				Result: result.ResultUnknown,
				ServerResults: []*result.ServerResult{
					result.NewServerResult(result.ResultUnknown, okChain[1].OCSPServer[0], TimeoutError{}),
				},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("expired ocsp response", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:        expiredChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}
		certResults, err := CheckStatus(opts)
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

	t.Run("pkixNoCheck missing", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, false)
		opts := Options{
			CertChain:        okChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}

		certResults, err := CheckStatus(opts)
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
		opts := Options{
			CertChain:        noHTTPChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}
		certResults, err := CheckStatus(opts)
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

func TestCheckOCSPInvalidChain(t *testing.T) {
	revokableTuples := testhelper.GetRevokableRSAChain(4)
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
		opts := Options{
			CertChain:        missingIntermediateChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}
		certResults, err := CheckStatus(opts)
		if err == nil || err.Error() != missingIntermediateErr.Error() {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", missingIntermediateErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("chain out of order", func(t *testing.T) {
		client := testhelper.MockClient(misorderedIntermediateTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:        misorderedIntermediateChain,
			CertChainPurpose: x509.ExtKeyUsageCodeSigning,
			SigningTime:      time.Now(),
			HTTPClient:       client,
		}
		certResults, err := CheckStatus(opts)
		if err == nil || err.Error() != misorderedChainErr.Error() {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", misorderedChainErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})
}
