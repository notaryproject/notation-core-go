package ocsp

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/testhelper"
	"golang.org/x/crypto/ocsp"
)

func identicalErrResults(errs, expectedErrs [][]error) bool {
	if len(errs) != len(expectedErrs) {
		return false
	}
	for i, serverErrs := range errs {
		if len(serverErrs) != len(expectedErrs[i]) {
			return false
		}
		for j, err := range serverErrs {
			if err == nil {
				if expectedErrs[i][j] == nil {
					continue
				} else {
					return false
				}
			} else if expectedErrs[i][j] == nil {
				return false
			}
			if err.Error() != expectedErrs[i][j].Error() {
				return false
			}
		}
	}

	return true
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

		err := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedErrs := [][]error{
			{nil},
		}
		if !identicalErrResults([][]error{err}, expectedErrs) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", err, expectedErrs[0])
		}
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		err := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedErrs := [][]error{
			{UnknownStatusError{}},
		}
		if !identicalErrResults([][]error{err}, expectedErrs) {
			t.Errorf("Expected certificate to have unknown status.\nReceived: %v\nExpected: %v\n", err, expectedErrs[0])
		}
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, nil, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		err := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedErrs := [][]error{
			{RevokedError{}},
		}
		if !identicalErrResults([][]error{err}, expectedErrs) {
			t.Errorf("Expected certificate to be revoked.\nReceived: %v\nExpected: %v\n", err, expectedErrs[0])
		}
	})
	t.Run("check OCSP future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, &revokedTime, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		err := certCheckStatus(revokableChain[0], revokableChain[1], opts)
		expectedErrs := [][]error{
			{nil},
		}
		if !identicalErrResults([][]error{err}, expectedErrs) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", err, expectedErrs[0])
		}
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

	chainRootErr := InvalidChainError{IsInvalidRoot: true, Err: errors.New("x509: invalid signature: parent certificate cannot sign this kind of certificate")}
	errs := CheckStatus(opts)
	expectedErrs := [][]error{
		{chainRootErr},
	}
	if !identicalErrResults(errs, expectedErrs) {
		t.Errorf("Expected invalid chain root error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
	}
}

func TestCheckStatusForRootCert(t *testing.T) {
	rootTuple := testhelper.GetRSARootCertificate()
	client := testhelper.MockClient([]testhelper.RSACertTuple{rootTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	opts := Options{
		CertChain:   []*x509.Certificate{rootTuple.Cert},
		SigningTime: time.Now(),
		HTTPClient:  client,
	}

	errs := CheckStatus(opts)
	expectedErrs := [][]error{
		{nil},
	}
	if !identicalErrResults(errs, expectedErrs) {
		t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
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
		errs := CheckStatus(opts)
		expectedErrs := [][]error{}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check non-revoked chain", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{nil},
			{nil},
			{nil},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check chain with 1 Unknown cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{nil},
			{nil},
			{UnknownStatusError{}},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected 3rd error to be UnknownStatus.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{nil},
			{nil},
			{RevokedError{}},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected 3rd cert to be Revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 unknown and 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{nil},
			{nil},
			{UnknownStatusError{}},
			{nil},
			{RevokedError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected 3rd error to be UnknownStatus and 5th to be Revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
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

		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{nil},
			{nil},
			{nil},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
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

		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{nil},
			{nil},
			{UnknownStatusError{}},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected 3rd error to be UnknownStatus.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 revoked cert after signing time", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		opts := Options{
			CertChain:   revokableChain,
			SigningTime: time.Now().Add(time.Hour),
			HTTPClient:  client,
		}

		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{nil},
			{nil},
			{RevokedError{}},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected 3rd error to be Revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
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

	backwardsChainErr := InvalidChainError{Err: errors.New("leaf certificate with subject \"CN=Notation Test RSA Root,O=Notary,L=Seattle,ST=WA,C=US\" is self-signed. Certificate chain must not contain self-signed leaf certificate")}
	chainRootErr := InvalidChainError{Err: errors.New("root certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\" is not self-signed. Certificate chain must end with a valid self-signed root certificate")}
	expiredRespErr := OCSPCheckError{Err: errors.New("expired OCSP response")}
	noHTTPErr := OCSPCheckError{Err: errors.New("OCSPServer must be accessible over HTTP")}

	t.Run("no OCSPServer specified", func(t *testing.T) {
		opts := Options{
			CertChain:   noOCSPChain,
			SigningTime: time.Now(),
			HTTPClient:  http.DefaultClient,
		}
		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{NoOCSPServerError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected NoOCSPServerError.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("chain missing root", func(t *testing.T) {
		opts := Options{
			CertChain:   noRootChain,
			SigningTime: time.Now(),
			HTTPClient:  http.DefaultClient,
		}
		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{chainRootErr},
			{chainRootErr},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected invalid chain root error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("backwards chain", func(t *testing.T) {
		opts := Options{
			CertChain:   backwardsChain,
			SigningTime: time.Now(),
			HTTPClient:  http.DefaultClient,
		}
		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{backwardsChainErr},
			{backwardsChainErr},
			{backwardsChainErr},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected invalid chain error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		timeoutClient := &http.Client{Timeout: 1 * time.Nanosecond}
		opts := Options{
			CertChain:   okChain,
			SigningTime: time.Now(),
			HTTPClient:  timeoutClient,
		}
		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{TimeoutError{}},
			{TimeoutError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected timeout errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("expired ocsp response", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   expiredChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}
		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{expiredRespErr},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected expired response errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("pkixNoCheck error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, false)
		opts := Options{
			CertChain:   okChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}

		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{PKIXNoCheckError{}},
			{PKIXNoCheckError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected expired response errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("non-HTTP URI error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   noHTTPChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}
		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{noHTTPErr},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected expired response errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
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

	missingIntermediateErr := InvalidChainError{Err: errors.New("certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 4,O=Notary,L=Seattle,ST=WA,C=US\" is not issued by \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\"")}
	misorderedChainErr := InvalidChainError{Err: errors.New("invalid certificates or certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 3,O=Notary,L=Seattle,ST=WA,C=US\" is not issued by \"CN=Notation Test Revokable RSA Chain Cert 4,O=Notary,L=Seattle,ST=WA,C=US\". Error: x509: invalid signature: parent certificate cannot sign this kind of certificate")}

	t.Run("chain missing intermediate", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   missingIntermediateChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}
		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{missingIntermediateErr},
			{missingIntermediateErr},
			{missingIntermediateErr},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected invalid chain error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("chain out of order", func(t *testing.T) {
		client := testhelper.MockClient(misorderedIntermediateTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:   misorderedIntermediateChain,
			SigningTime: time.Now(),
			HTTPClient:  client,
		}
		errs := CheckStatus(opts)
		expectedErrs := [][]error{
			{misorderedChainErr},
			{misorderedChainErr},
			{misorderedChainErr},
			{misorderedChainErr},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected invalid chain error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
}
