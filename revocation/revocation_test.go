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

func TestCheckRevocationStatusForSingleCert(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	revokableChain := []*x509.Certificate{revokableCertTuple.Cert, revokableIssuerTuple.Cert}
	testChain := []testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}

	t.Run("check non-revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.UnknownStatusError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected certificate to have unknown status.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, nil, true)
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.RevokedError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected certificate to be revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, &revokedTime, true)
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
}

func TestCheckRevocationStatusForSelfSignedCert(t *testing.T) {
	selfSignedTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation revocation test self-signed cert")
	client := testhelper.MockClient([]testhelper.RSACertTuple{selfSignedTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	r := New(client)

	chainRootErr := revocation_ocsp.OCSPCheckError{Err: errors.New("invalid chain: expected chain to end with root cert: x509: invalid signature: parent certificate cannot sign this kind of certificate")}
	errs := r.Validate([]*x509.Certificate{selfSignedTuple.Cert}, time.Now())
	expectedErrs := [][]error{
		{chainRootErr},
	}
	if !identicalErrResults(errs, expectedErrs) {
		t.Errorf("Expected invalid chain root error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
	}
}

func TestCheckRevocationStatusForRootCert(t *testing.T) {
	rootTuple := testhelper.GetRSARootCertificate()
	client := testhelper.MockClient([]testhelper.RSACertTuple{rootTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	r := New(client)

	errs := r.Validate([]*x509.Certificate{rootTuple.Cert}, time.Now())
	expectedErrs := [][]error{
		{nil},
	}
	if !identicalErrResults(errs, expectedErrs) {
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
		r := New(nil)
		errs := r.Validate([]*x509.Certificate{}, time.Now())
		expectedErrs := [][]error{}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected no errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check non-revoked chain", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
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
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.UnknownStatusError{}},
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
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.RevokedError{}},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected 3rd error to be Revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 unknown and 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.UnknownStatusError{}},
			{nil},
			{revocation_ocsp.RevokedError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected 3rd error to be UnknownStatus and 5th to be Revoked.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be future revoked, the rest will be good
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
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
		// 3rd cert will be unknown, 5th will be future revoked, the rest will be good
		r := New(client)

		errs := r.Validate(revokableChain, time.Now())
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.UnknownStatusError{}},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected 3rd error to be UnknownStatus.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})
	t.Run("check OCSP with 1 revoked cert before signing time", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		r := New(client)

		errs := r.Validate(revokableChain, time.Now().Add(time.Hour))
		expectedErrs := [][]error{
			{nil},
			{nil},
			{revocation_ocsp.RevokedError{}},
			{nil},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
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
	expiredLeaf.OCSPServer = []string{"http://example.com/expired_ocsp"}
	expiredChain := []*x509.Certificate{expiredLeaf, revokableTuples[1].Cert, revokableTuples[2].Cert}

	noHTTPLeaf, _ := x509.ParseCertificate(revokableTuples[0].Cert.Raw)
	noHTTPLeaf.OCSPServer = []string{"ldap://ds.example.com:123/chain_ocsp/0"}
	noHTTPChain := []*x509.Certificate{noHTTPLeaf, revokableTuples[1].Cert, revokableTuples[2].Cert}

	invalidChainErr := revocation_ocsp.OCSPCheckError{Err: errors.New("invalid chain: expected chain to be correct and complete: parent's subject does not match issuer for a cert in the chain")}
	chainRootErr := revocation_ocsp.OCSPCheckError{Err: errors.New("invalid chain: expected chain to end with root cert: parent's subject does not match issuer for a cert in the chain")}
	expiredRespErr := revocation_ocsp.OCSPCheckError{Err: errors.New("expired OCSP response")}
	noHTTPErr := revocation_ocsp.OCSPCheckError{Err: errors.New("OCSPServer must be accessible over HTTP")}

	r := New(nil)

	t.Run("no OCSPServer specified", func(t *testing.T) {
		errs := r.Validate(noOCSPChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.NoOCSPServerError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected revocation_ocsp.NoOCSPServerError.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("chain missing root", func(t *testing.T) {
		errs := r.Validate(noRootChain, time.Now())
		expectedErrs := [][]error{
			{chainRootErr},
			{chainRootErr},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected invalid chain root error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("backwards chain", func(t *testing.T) {
		errs := r.Validate(backwardsChain, time.Now())
		expectedErrs := [][]error{
			{invalidChainErr},
			{invalidChainErr},
			{invalidChainErr},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected invalid chain error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		timeoutClient := &http.Client{Timeout: 1 * time.Nanosecond}
		timeoutR := New(timeoutClient)
		errs := timeoutR.Validate(okChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.TimeoutError{}},
			{revocation_ocsp.TimeoutError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected timeout errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("expired ocsp response", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		expiredR := New(client)
		errs := expiredR.Validate(expiredChain, time.Now())
		expectedErrs := [][]error{
			{expiredRespErr},
			{nil},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected expired response errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("OCSP pkixNoCheck error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, false)
		r := New(client)

		errs := r.Validate(okChain, time.Now())
		expectedErrs := [][]error{
			{revocation_ocsp.PKIXNoCheckError{}},
			{revocation_ocsp.PKIXNoCheckError{}},
			{nil},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected expired response errors.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("non-HTTP URI error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r := New(client)
		errs := r.Validate(noHTTPChain, time.Now())
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

	invalidChainErr := revocation_ocsp.OCSPCheckError{Err: errors.New("invalid chain: expected chain to be correct and complete: parent's subject does not match issuer for a cert in the chain")}

	t.Run("chain missing intermediate", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r := New(client)

		errs := r.Validate(missingIntermediateChain, time.Now())
		expectedErrs := [][]error{
			{invalidChainErr},
			{invalidChainErr},
			{invalidChainErr},
		}
		if !identicalErrResults(errs, expectedErrs) {
			t.Errorf("Expected invalid chain error.\nReceived: %v\nExpected: %v\n", errs, expectedErrs)
		}
	})

	t.Run("chain out of order", func(t *testing.T) {
		client := testhelper.MockClient(misorderedIntermediateTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		r := New(client)

		errs := r.Validate(misorderedIntermediateChain, time.Now())
		expectedErrs := [][]error{
			{invalidChainErr},
			{invalidChainErr},
			{invalidChainErr},
			{invalidChainErr},
		}
		if !identicalErrResults(errs, expectedErrs) {
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

func TestResultFromErrorsSingle(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}})
		if result != OK {
			t.Errorf("Expected %s but got %s", OK, result)
		}
	})
	t.Run("no ocsp server", func(t *testing.T) {
		result := ResultFromErrors([][]error{{revocation_ocsp.NoOCSPServerError{}}})
		if result != OK {
			t.Errorf("Expected %s but got %s", OK, result)
		}
	})
	t.Run("ocsp unknown status", func(t *testing.T) {
		result := ResultFromErrors([][]error{{revocation_ocsp.UnknownStatusError{}}})
		if result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result)
		}
	})
	t.Run("check ocsp err", func(t *testing.T) {
		result := ResultFromErrors([][]error{{revocation_ocsp.OCSPCheckError{}}})
		if result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result)
		}
	})
	t.Run("ocsp pkix no check", func(t *testing.T) {
		result := ResultFromErrors([][]error{{revocation_ocsp.PKIXNoCheckError{}}})
		if result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result)
		}
	})
	t.Run("ocsp timeout", func(t *testing.T) {
		result := ResultFromErrors([][]error{{revocation_ocsp.TimeoutError{}}})
		if result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result)
		}
	})
	t.Run("ocsp revoked", func(t *testing.T) {
		result := ResultFromErrors([][]error{{revocation_ocsp.RevokedError{}}})
		if result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result)
		}
	})
}

func TestResultFromErrorsMultiple(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {nil}, {nil}})
		if result != OK {
			t.Errorf("Expected %s but got %s", OK, result)
		}
	})
	t.Run("only ok errors (single server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {revocation_ocsp.NoOCSPServerError{}}, {nil}})
		if result != OK {
			t.Errorf("Expected %s but got %s", OK, result)
		}
	})
	t.Run("only ok errors (multi server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {nil, nil}, {revocation_ocsp.NoOCSPServerError{}, nil}, {revocation_ocsp.NoOCSPServerError{}, revocation_ocsp.NoOCSPServerError{}}, {nil, revocation_ocsp.NoOCSPServerError{}}, {nil}})
		if result != OK {
			t.Errorf("Expected %s but got %s", OK, result)
		}
	})
	t.Run("ok and unknown errors (single server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {revocation_ocsp.UnknownStatusError{}}, {revocation_ocsp.NoOCSPServerError{}}, {nil}})
		if result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result)
		}
	})
	t.Run("ok and unknown errors (multi server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {revocation_ocsp.NoOCSPServerError{}, revocation_ocsp.TimeoutError{}}, {nil}})
		if result != Unknown {
			t.Errorf("Expected %s but got %s", Unknown, result)
		}
	})
	t.Run("ok and revoked errors (single server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {revocation_ocsp.RevokedError{}}, {revocation_ocsp.NoOCSPServerError{}}, {nil}})
		if result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result)
		}
	})
	t.Run("ok and revoked errors (multi server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {revocation_ocsp.NoOCSPServerError{}, revocation_ocsp.RevokedError{}}, {nil}})
		if result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result)
		}
	})
	t.Run("unknown and revoked errors (single server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{revocation_ocsp.RevokedError{}}, {revocation_ocsp.UnknownStatusError{}}, {nil}})
		if result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result)
		}
	})
	t.Run("unknown and revoked errors (multi server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{revocation_ocsp.RevokedError{}, revocation_ocsp.UnknownStatusError{}}})
		if result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result)
		}
	})
	t.Run("all three types (single server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {revocation_ocsp.RevokedError{}}, {revocation_ocsp.UnknownStatusError{}}, {revocation_ocsp.NoOCSPServerError{}}, {nil}})
		if result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result)
		}
	})
	t.Run("all three types (multi server)", func(t *testing.T) {
		result := ResultFromErrors([][]error{{nil}, {revocation_ocsp.RevokedError{}, revocation_ocsp.UnknownStatusError{}, revocation_ocsp.NoOCSPServerError{}}, {nil}})
		if result != Revoked {
			t.Errorf("Expected %s but got %s", Revoked, result)
		}
	})
}
