package ocsp

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/base"
	"github.com/notaryproject/notation-core-go/testhelper"
	"golang.org/x/crypto/ocsp"
)

func validateEquivalentCertResults(certResults, expectedCertResults []*base.CertRevocationResult, t *testing.T) {
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

func getOKCertResult() *base.CertRevocationResult {
	return &base.CertRevocationResult{
		Result: base.ResultOK,
		ServerResults: []*base.ServerResult{{
			Result: base.ResultOK,
			Error:  nil,
		}},
	}
}

func getRootCertResult() *base.CertRevocationResult {
	return &base.CertRevocationResult{
		Result: base.ResultNonRevokable,
		ServerResults: []*base.ServerResult{{
			Result: base.ResultNonRevokable,
			Error:  nil,
		}},
	}
}

func TestCheckStatus(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	revokableChain := []*x509.Certificate{revokableCertTuple.Cert, revokableIssuerTuple.Cert}
	testChain := []testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}

	t.Run("check non-revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*base.CertRevocationResult{getOKCertResult()}
		validateEquivalentCertResults([]*base.CertRevocationResult{certResult}, expectedCertResults, t)
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*base.CertRevocationResult{{
			Result: base.ResultUnknown,
			ServerResults: []*base.ServerResult{{
				Result: base.ResultUnknown,
				Error:  UnknownStatusError{},
			}},
		}}
		validateEquivalentCertResults([]*base.CertRevocationResult{certResult}, expectedCertResults, t)
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, nil, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*base.CertRevocationResult{{
			Result: base.ResultRevoked,
			ServerResults: []*base.ServerResult{{
				Result: base.ResultRevoked,
				Error:  RevokedError{},
			}},
		}}
		validateEquivalentCertResults([]*base.CertRevocationResult{certResult}, expectedCertResults, t)
	})
	t.Run("check OCSP future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, &revokedTime, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResult := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedCertResults := []*base.CertRevocationResult{getOKCertResult()}
		validateEquivalentCertResults([]*base.CertRevocationResult{certResult}, expectedCertResults, t)
	})
}

func TestCheckStatusForSelfSignedCert(t *testing.T) {
	selfSignedTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation revocation test self-signed cert")
	client := testhelper.MockClient([]testhelper.RSACertTuple{selfSignedTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	opts := Options{
		CertChain:   []*x509.Certificate{selfSignedTuple.Cert},
		SigningTime: time.Now(),
		HTTPClient:  client,
	}

	certResults, err := CheckStatus(opts)
	if err != nil {
		t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
	}
	expectedCertResults := []*base.CertRevocationResult{getRootCertResult()}
	validateEquivalentCertResults(certResults, expectedCertResults, t)
}

func TestCheckStatusForRootCert(t *testing.T) {
	rootTuple := testhelper.GetRSARootCertificate()
	client := testhelper.MockClient([]testhelper.RSACertTuple{rootTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	opts := Options{
		CertChain:   []*x509.Certificate{rootTuple.Cert},
		SigningTime: time.Now(),
		HTTPClient:  client,
	}

	certResults, err := CheckStatus(opts)
	expectedErr := base.InvalidChainError{Err: errors.New("invalid self-signed certificate. Error: certificate with subject \"CN=Notation Test RSA Root,O=Notary,L=Seattle,ST=WA,C=US\": if the basic constraints extension is present, the ca field must be set to false")}
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
		CertChain:   []*x509.Certificate{certTuple.Cert},
		SigningTime: time.Now(),
		HTTPClient:  client,
	}

	certResults, err := CheckStatus(opts)
	expectedErr := base.InvalidChainError{Err: errors.New("invalid self-signed certificate. subject: \"CN=Notation Test RSA Leaf Cert,O=Notary,L=Seattle,ST=WA,C=US\". Error: crypto/rsa: verification error")}
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected CheckStatus to fail with %v, but got: %v", expectedErr, err)
	}
	if certResults != nil {
		t.Error("Expected certResults to be nil when there is an error")
	}
}

func TestCheckStatusForChain(t *testing.T) {
	testChain := testhelper.GetRevokableRSAChain(6)
	revokableChain := make([]*x509.Certificate, 6)
	for i, tuple := range testChain {
		revokableChain[i] = tuple.Cert
	}

	t.Run("empty chain", func(t *testing.T) {
		opts := Options{
			CertChain:   []*x509.Certificate{},
			SigningTime: time.Now(),
			HTTPClient:  http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check non-revoked chain", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			getOKCertResult(),
			getOKCertResult(),
			getOKCertResult(),
			getOKCertResult(),
			getOKCertResult(),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check chain with 1 Unknown cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			getOKCertResult(),
			getOKCertResult(),
			{
				Result: base.ResultUnknown,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultUnknown,
					Error:  UnknownStatusError{},
				}},
			},
			getOKCertResult(),
			getOKCertResult(),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			getOKCertResult(),
			getOKCertResult(),
			{
				Result: base.ResultRevoked,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultRevoked,
					Error:  RevokedError{},
				}},
			},
			getOKCertResult(),
			getOKCertResult(),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 unknown and 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			getOKCertResult(),
			getOKCertResult(),
			{
				Result: base.ResultUnknown,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultUnknown,
					Error:  UnknownStatusError{},
				}},
			},
			getOKCertResult(),
			{
				Result: base.ResultRevoked,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultRevoked,
					Error:  RevokedError{},
				}},
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
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			getOKCertResult(),
			getOKCertResult(),
			getOKCertResult(),
			getOKCertResult(),
			getOKCertResult(),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 unknown and 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			getOKCertResult(),
			getOKCertResult(),
			{
				Result: base.ResultUnknown,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultUnknown,
					Error:  UnknownStatusError{},
				}},
			},
			getOKCertResult(),
			getOKCertResult(),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})
	t.Run("check OCSP with 1 revoked cert after signing time", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now().Add(time.Hour),
			HTTPClient:  client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			getOKCertResult(),
			getOKCertResult(),
			{
				Result: base.ResultRevoked,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultRevoked,
					Error:  RevokedError{},
				}},
			},
			getOKCertResult(),
			getOKCertResult(),
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

	backwardsChainErr := base.InvalidChainError{Err: errors.New("leaf certificate with subject \"CN=Notation Test RSA Root,O=Notary,L=Seattle,ST=WA,C=US\" is self-signed. Certificate chain must not contain self-signed leaf certificate")}
	chainRootErr := base.InvalidChainError{Err: errors.New("root certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\" is not self-signed. Certificate chain must end with a valid self-signed root certificate")}
	expiredRespErr := OCSPCheckError{Err: errors.New("expired OCSP response")}
	noHTTPErr := OCSPCheckError{Err: errors.New("OCSPServer protocol ldap is not supported")}

	t.Run("no OCSPServer specified", func(t *testing.T) {
		opts := Options{
			CertChain:   noOCSPChain,
			SigningTime: time.Now(),
			HTTPClient:  http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			{
				Result: base.ResultNonRevokable,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultNonRevokable,
					Error:  nil,
				}},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("chain missing root", func(t *testing.T) {
		opts := Options{
			CertChain:   noRootChain,
			SigningTime: time.Now(),
			HTTPClient:  http.DefaultClient,
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
			CertChain:   backwardsChain,
			SigningTime: time.Now(),
			HTTPClient:  http.DefaultClient,
		}
		certResults, err := CheckStatus(opts)
		if err == nil || err.Error() != backwardsChainErr.Error() {
			t.Errorf("Expected CheckStatus to fail with %v, but got: %v", backwardsChainErr, err)
		}
		if certResults != nil {
			t.Error("Expected certResults to be nil when there is an error")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		timeoutClient := &http.Client{Timeout: 1 * time.Nanosecond}
		opts := Options{
			CertChain:   okChain,
			SigningTime: time.Now(),
			HTTPClient:  timeoutClient,
		}
		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			{
				Result: base.ResultUnknown,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultUnknown,
					Error:  TimeoutError{},
				}},
			},
			{
				Result: base.ResultUnknown,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultUnknown,
					Error:  TimeoutError{},
				}},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("expired ocsp response", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   expiredChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}
		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			{
				Result: base.ResultUnknown,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultUnknown,
					Error:  expiredRespErr,
				}},
			},
			getOKCertResult(),
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("pkixNoCheck error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, false)
		opts := Options{
			CertChain:   okChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			{
				Result: base.ResultNonRevokable,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultNonRevokable,
					Error:  nil,
				}},
			},
			{
				Result: base.ResultNonRevokable,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultNonRevokable,
					Error:  nil,
				}},
			},
			getRootCertResult(),
		}
		validateEquivalentCertResults(certResults, expectedCertResults, t)
	})

	t.Run("non-HTTP URI error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   noHTTPChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}
		certResults, err := CheckStatus(opts)
		if err != nil {
			t.Errorf("Expected CheckStatus to succeed, but got error: %v", err)
		}
		expectedCertResults := []*base.CertRevocationResult{
			{
				Result: base.ResultUnknown,
				ServerResults: []*base.ServerResult{{
					Result: base.ResultUnknown,
					Error:  noHTTPErr,
				}},
			},
			getOKCertResult(),
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

	missingIntermediateErr := base.InvalidChainError{Err: errors.New("certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 4,O=Notary,L=Seattle,ST=WA,C=US\" is not issued by \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\"")}
	misorderedChainErr := base.InvalidChainError{Err: errors.New("invalid certificates or certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 3,O=Notary,L=Seattle,ST=WA,C=US\" is not issued by \"CN=Notation Test Revokable RSA Chain Cert 4,O=Notary,L=Seattle,ST=WA,C=US\". Error: x509: invalid signature: parent certificate cannot sign this kind of certificate")}

	t.Run("chain missing intermediate", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   missingIntermediateChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
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
			CertChain:   misorderedIntermediateChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
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

func TestMultipleServerCertResults(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		serverResults := []*base.ServerResult{
			{
				Result: base.ResultOK,
				Error:  nil,
			},
			{
				Result: base.ResultOK,
				Error:  nil,
			},
			{
				Result: base.ResultOK,
				Error:  nil,
			},
		}
		expectedResult := []*base.CertRevocationResult{{
			Result:        base.ResultOK,
			ServerResults: serverResults,
		}}
		result := serverResultsToCertRevocationResult(serverResults)
		validateEquivalentCertResults([]*base.CertRevocationResult{result}, expectedResult, t)
	})
	t.Run("only non-revocable errors (multi server)", func(t *testing.T) {
		serverResults := []*base.ServerResult{
			{
				Result: base.ResultNonRevokable,
				Error:  nil,
			},
			{
				Result: base.ResultNonRevokable,
				Error:  nil,
			},
		}
		expectedResult := []*base.CertRevocationResult{{
			Result:        base.ResultNonRevokable,
			ServerResults: serverResults,
		}}
		result := serverResultsToCertRevocationResult(serverResults)
		validateEquivalentCertResults([]*base.CertRevocationResult{result}, expectedResult, t)
	})
	t.Run("non-revocable and unknown errors (multi server)", func(t *testing.T) {
		serverResults := []*base.ServerResult{
			{
				Result: base.ResultNonRevokable,
				Error:  nil,
			},
			{
				Result: base.ResultUnknown,
				Error:  TimeoutError{},
			},
		}
		expectedResult := []*base.CertRevocationResult{{
			Result:        base.ResultUnknown,
			ServerResults: serverResults,
		}}
		result := serverResultsToCertRevocationResult(serverResults)
		validateEquivalentCertResults([]*base.CertRevocationResult{result}, expectedResult, t)
	})
	t.Run("non-revocable and revoked errors (multi server)", func(t *testing.T) {
		serverResults := []*base.ServerResult{
			{
				Result: base.ResultNonRevokable,
				Error:  nil,
			},
			{
				Result: base.ResultRevoked,
				Error:  RevokedError{},
			},
		}
		expectedResult := []*base.CertRevocationResult{{
			Result:        base.ResultRevoked,
			ServerResults: serverResults,
		}}
		result := serverResultsToCertRevocationResult(serverResults)
		validateEquivalentCertResults([]*base.CertRevocationResult{result}, expectedResult, t)
	})
	t.Run("unknown and revoked errors (multi server)", func(t *testing.T) {
		serverResults := []*base.ServerResult{
			{
				Result: base.ResultRevoked,
				Error:  RevokedError{},
			},
			{
				Result: base.ResultUnknown,
				Error:  UnknownStatusError{},
			},
		}
		expectedResult := []*base.CertRevocationResult{{
			Result:        base.ResultRevoked,
			ServerResults: serverResults,
		}}
		result := serverResultsToCertRevocationResult(serverResults)
		validateEquivalentCertResults([]*base.CertRevocationResult{result}, expectedResult, t)
	})
	t.Run("all three types (multi server)", func(t *testing.T) {
		serverResults := []*base.ServerResult{
			{
				Result: base.ResultRevoked,
				Error:  RevokedError{},
			},
			{
				Result: base.ResultUnknown,
				Error:  UnknownStatusError{},
			},
			{
				Result: base.ResultNonRevokable,
				Error:  nil,
			},
		}
		expectedResult := []*base.CertRevocationResult{{
			Result:        base.ResultRevoked,
			ServerResults: serverResults,
		}}
		result := serverResultsToCertRevocationResult(serverResults)
		validateEquivalentCertResults([]*base.CertRevocationResult{result}, expectedResult, t)
	})
}
