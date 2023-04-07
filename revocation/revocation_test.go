package revocation

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	revocation_ocsp "github.com/notaryproject/notation-core-go/revocation/ocsp"
	"github.com/notaryproject/notation-core-go/testhelper"
	"golang.org/x/crypto/ocsp"
)

func errToResult(err error) Result {
	if err == nil || errors.Is(err, revocation_ocsp.NoOCSPServerError{}) {
		return OK
	} else if errors.Is(err, revocation_ocsp.RevokedError{}) {
		return Revoked
	} else {
		// Includes ocsp.OCSPCheckError, ocsp.UnknownStatusError,
		// ocsp.PKIXNoCheckError, InvalidChainError, and ocsp.TimeoutError
		return Unknown
	}
}

func identicalErrResults(certResults []*CertRevocationResult, expectedErrs [][]error, expectedResults []Result) bool {
	if len(certResults) != len(expectedErrs) || len(certResults) != len(expectedResults) {
		return false
	}
	for i, certResult := range certResults {

		if len(certResult.ServerResults) != len(expectedErrs[i]) {
			return false
		}
		for j, serverResult := range certResult.ServerResults {
			if serverResult.Error == nil {
				if expectedErrs[i][j] == nil {
					continue
				} else {
					return false
				}
			} else if expectedErrs[i][j] == nil {
				return false
			}
			if serverResult.Error.Error() != expectedErrs[i][j].Error() {
				return false
			}
			if serverResult.Result != errToResult(expectedErrs[i][j]) {
				return false
			}
		}
		if certResult.Result != expectedResults[i] {
			return false
		}
	}

	return true
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
	} else if revR.httpClient != client {
		t.Errorf("Expected New to set client to %v, but it was set to %v", client, revR.httpClient)
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

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
		}
		expectedResults := []Result{OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.UnknownStatusError{}},
			{nil},
		}
		expectedResults := []Result{Unknown, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected certificate to have unknown status.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.RevokedError{}},
			{nil},
		}
		expectedResults := []Result{Revoked, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected certificate to be revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, &revokedTime, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
		}
		expectedResults := []Result{OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
}

func TestCheckRevocationStatusForSelfSignedCert(t *testing.T) {
	selfSignedTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation revocation test self-signed cert")
	client := testhelper.MockClient([]testhelper.RSACertTuple{selfSignedTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	r, err := New(client)
	if err != nil {
		t.Errorf("Expected successful creation of revocation, but received error: %v", err)
	}

	chainRootErr := revocation_ocsp.InvalidChainError{IsInvalidRoot: true, Err: errors.New("x509: invalid signature: parent certificate cannot sign this kind of certificate")}
	errs := r.Validate([]*x509.Certificate{selfSignedTuple.Cert}, time.Now())
	expectedErrs := [][]error{
		{chainRootErr},
	}
	expectedResults := []Result{Unknown}
	if !identicalErrResults(errs, expectedErrs, expectedResults) {
		t.Errorf("Expected invalid chain root error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
	}
}

func TestCheckRevocationStatusForRootCert(t *testing.T) {
	rootTuple := testhelper.GetRSARootCertificate()
	client := testhelper.MockClient([]testhelper.RSACertTuple{rootTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	r, err := New(client)
	if err != nil {
		t.Errorf("Expected successful creation of revocation, but received error: %v", err)
	}

	errs := r.Validate([]*x509.Certificate{rootTuple.Cert}, time.Now())
	expectedErrs := [][]error{
		{nil},
	}
	expectedResults := []Result{OK}
	if !identicalErrResults(errs, expectedErrs, expectedResults) {
		t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
	}
}

func TestCheckRevocationStatusForChain(t *testing.T) {
	testChain := testhelper.GetRevokableRSAChain(6)
	revokableChain := make([]*x509.Certificate, 6)
	for i, tuple := range testChain {
		revokableChain[i] = tuple.Cert
	}

	t.Run("empty chain", func(t *testing.T) {
		r, err := New(&http.Client{Timeout: 5 * time.Second})
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		errs := r.Validate([]*x509.Certificate{}, time.Now())
		expectedErrs := [][]error{}
		expectedResults := []Result{}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check non-revoked chain", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{nil},
			{nil},
			{nil},
			{nil},
		}
		expectedResults := []Result{OK, OK, OK, OK, OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check chain with 1 Unknown cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.UnknownStatusError{}},
			{nil},
			{nil},
			{nil},
		}
		expectedResults := []Result{OK, OK, Unknown, OK, OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected 3rd error to be UnknownStatus.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.RevokedError{}},
			{nil},
			{nil},
			{nil},
		}
		expectedResults := []Result{OK, OK, Revoked, OK, OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected 3rd error to be Revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 unknown and 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.UnknownStatusError{}},
			{nil},
			{revocation_ocsp.RevokedError{}},
			{nil},
		}
		expectedResults := []Result{OK, OK, Unknown, OK, Revoked, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected 3rd error to be UnknownStatus and 5th to be Revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be future revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{nil},
			{nil},
			{nil},
			{nil},
		}
		expectedResults := []Result{OK, OK, OK, OK, OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 unknown and 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be unknown, 5th will be future revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.UnknownStatusError{}},
			{nil},
			{nil},
			{nil},
		}
		expectedResults := []Result{OK, OK, Unknown, OK, OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected 3rd error to be UnknownStatus.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 revoked cert before signing time", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(revokableChain, time.Now().Add(time.Hour))
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.RevokedError{}},
			{nil},
			{nil},
			{nil},
		}
		expectedResults := []Result{OK, OK, Revoked, OK, OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected 3rd error to be Revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
}

func TestCheckRevocationErrors(t *testing.T) {
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

	backwardsChainErr := revocation_ocsp.InvalidChainError{Err: errors.New("leaf certificate with subject \"CN=Notation Test RSA Root,O=Notary,L=Seattle,ST=WA,C=US\" is self-signed. Certificate chain must not contain self-signed leaf certificate")}
	chainRootErr := revocation_ocsp.InvalidChainError{Err: errors.New("root certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\" is not self-signed. Certificate chain must end with a valid self-signed root certificate")}
	expiredRespErr := revocation_ocsp.OCSPCheckError{Err: errors.New("expired OCSP response")}
	noHTTPErr := revocation_ocsp.OCSPCheckError{Err: errors.New("OCSPServer must be accessible over HTTP")}

	r, err := New(&http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Errorf("Expected successful creation of revocation, but received error: %v", err)
	}

	t.Run("no OCSPServer specified", func(t *testing.T) {
		errs := r.Validate(noOCSPChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.NoOCSPServerError{}},
			{nil},
		}
		expectedResults := []Result{OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected revocation_ocsp.NoOCSPServerError.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("chain missing root", func(t *testing.T) {
		errs := r.Validate(noRootChain, time.Now())
		expectedErrs := [][]error{
			{chainRootErr},
			{chainRootErr},
		}
		expectedResults := []Result{Unknown, Unknown}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected invalid chain root error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("backwards chain", func(t *testing.T) {
		errs := r.Validate(backwardsChain, time.Now())
		expectedErrs := [][]error{
			{backwardsChainErr},
			{backwardsChainErr},
			{backwardsChainErr},
		}
		expectedResults := []Result{Unknown, Unknown, Unknown}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected invalid chain error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		timeoutClient := &http.Client{Timeout: 1 * time.Nanosecond}
		timeoutR, err := New(timeoutClient)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		errs := timeoutR.Validate(okChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.TimeoutError{}},
			{revocation_ocsp.TimeoutError{}},
			{nil},
		}
		expectedResults := []Result{Unknown, Unknown, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected timeout errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("expired ocsp response", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		expiredR, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		errs := expiredR.Validate(expiredChain, time.Now())
		expectedErrs := [][]error{
			{expiredRespErr},
			{nil},
			{nil},
		}
		expectedResults := []Result{Unknown, OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected expired response errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("OCSP pkixNoCheck error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, false)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(okChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.PKIXNoCheckError{}},
			{revocation_ocsp.PKIXNoCheckError{}},
			{nil},
		}
		expectedResults := []Result{Unknown, Unknown, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected expired response errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("non-HTTP URI error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}
		errs := r.Validate(noHTTPChain, time.Now())
		expectedErrs := [][]error{
			{noHTTPErr},
			{nil},
			{nil},
		}
		expectedResults := []Result{Unknown, OK, OK}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected expired response errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
}

func TestCheckRevocationInvalidChain(t *testing.T) {
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

	missingIntermediateErr := revocation_ocsp.InvalidChainError{Err: errors.New("certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 4,O=Notary,L=Seattle,ST=WA,C=US\" is not issued by \"CN=Notation Test Revokable RSA Chain Cert 2,O=Notary,L=Seattle,ST=WA,C=US\"")}
	misorderedChainErr := revocation_ocsp.InvalidChainError{Err: errors.New("invalid certificates or certificate with subject \"CN=Notation Test Revokable RSA Chain Cert 3,O=Notary,L=Seattle,ST=WA,C=US\" is not issued by \"CN=Notation Test Revokable RSA Chain Cert 4,O=Notary,L=Seattle,ST=WA,C=US\". Error: x509: invalid signature: parent certificate cannot sign this kind of certificate")}

	t.Run("chain missing intermediate", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(missingIntermediateChain, time.Now())
		expectedErrs := [][]error{
			{missingIntermediateErr},
			{missingIntermediateErr},
			{missingIntermediateErr},
		}
		expectedResults := []Result{Unknown, Unknown, Unknown}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected invalid chain error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("chain out of order", func(t *testing.T) {
		client := testhelper.MockClient(misorderedIntermediateTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r, err := New(client)
		if err != nil {
			t.Errorf("Expected successful creation of revocation, but received error: %v", err)
		}

		errs := r.Validate(misorderedIntermediateChain, time.Now())
		expectedErrs := [][]error{
			{misorderedChainErr},
			{misorderedChainErr},
			{misorderedChainErr},
			{misorderedChainErr},
		}
		expectedResults := []Result{Unknown, Unknown, Unknown, Unknown}
		if !identicalErrResults(errs, expectedErrs, expectedResults) {
			t.Errorf("Expected invalid chain error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
}

func TestResultString(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		if OK.String() != "OK" {
			t.Errorf("Expected %s but got %s", "OK", OK.String())
		}
	})
	t.Run("unknown", func(t *testing.T) {
		if Unknown.String() != "Unknown" {
			t.Errorf("Expected %s but got %s", "Unknown", Unknown.String())
		}
	})
	t.Run("revoked", func(t *testing.T) {
		if Revoked.String() != "Revoked" {
			t.Errorf("Expected %s but got %s", "Revoked", Revoked.String())
		}
	})
	t.Run("invalid result", func(t *testing.T) {
		if Result(3).String() != "Invalid Result" {
			t.Errorf("Expected %s but got %s", "Invalid Result", Result(3).String())
		}
	})
}

func equivalentErrorList(certResult CertRevocationResult, errs []error) bool {
	for i, serverResult := range certResult.ServerResults {
		if !errors.Is(serverResult.Error, errs[i]) {
			return false
		}
	}
	return true
}

func TestServerErrsToCertRevocationResultSingle(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		expectedErrs := []error{nil}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != OK {
			t.Errorf("Expected %s but got %s", OK, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("no ocsp server", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.NoOCSPServerError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != OK {
			t.Errorf("Expected %s but got %s", OK, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("ocsp unknown status", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.UnknownStatusError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("check ocsp err", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.OCSPCheckError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("ocsp pkix no check", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.PKIXNoCheckError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("ocsp timeout", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.TimeoutError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("ocsp revoked", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.RevokedError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
}

func TestServerErrsToCertRevocationResultMultiple(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		expectedErrs := []error{nil, nil, nil}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != OK {
			t.Errorf("Expected %s but got %s", OK, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("only ok errors (multi server)", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.NoOCSPServerError{}, nil}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != OK {
			t.Errorf("Expected %s but got %s", OK, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("ok and unknown errors (multi server)", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.NoOCSPServerError{}, revocation_ocsp.TimeoutError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("ok and revoked errors (multi server)", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.NoOCSPServerError{}, revocation_ocsp.RevokedError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("unknown and revoked errors (multi server)", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.RevokedError{}, revocation_ocsp.UnknownStatusError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
	t.Run("all three types (multi server)", func(t *testing.T) {
		expectedErrs := []error{revocation_ocsp.RevokedError{}, revocation_ocsp.UnknownStatusError{}, revocation_ocsp.NoOCSPServerError{}}
		result := serverErrsToCertRevocationResult(expectedErrs)
		if result.Result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result.Result)
		}
		if !equivalentErrorList(*result, expectedErrs) {
			t.Error("Errors for result did not match expected errors")
		}
	})
}