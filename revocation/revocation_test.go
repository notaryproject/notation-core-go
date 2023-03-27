package revocation

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

func TestCheckRevocationStatusForSingleCert(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	revokableChain := []*x509.Certificate{revokableCertTuple.Cert, revokableIssuerTuple.Cert}
	testChain := []testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}

	t.Run("check non-revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil)
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil)
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			if _, ok := err.(UnknownInOCSPError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, nil)
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			if _, ok := err.(RevokedInOCSPError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, &revokedTime)
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
}

func TestCheckRevocationStatusForChain(t *testing.T) {
	testChain := testhelper.GetRevokableRSAChain(6)
	revokableChain := make([]*x509.Certificate, 6)
	for i, tuple := range testChain {
		revokableChain[i] = tuple.Cert
	}

	t.Run("empty chain", func(t *testing.T) {
		r := NewRevocation(nil)
		err := r.Validate([]*x509.Certificate{})
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})

	t.Run("check non-revoked chain", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil)
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
	t.Run("check chain with 1 Unknown cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good}, nil)
		// 3rd cert will be unknown, the rest will be good
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			if _, ok := err.(UnknownInOCSPError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP with 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil)
		// 3rd cert will be revoked, the rest will be good
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			if _, ok := err.(RevokedInOCSPError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP with 1 unknown and 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			if _, ok := err.(RevokedInOCSPError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP with 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime)
		// 3rd cert will be revoked, the rest will be good
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
	t.Run("check OCSP with 1 unknown and 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		r := NewRevocation(client)

		err := r.Validate(revokableChain)
		if err != nil {
			if _, ok := err.(UnknownInOCSPError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
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

	expiredLeaf := revokableTuples[0].Cert
	expiredLeaf.OCSPServer = []string{"http://localhost:8080/expired_ocsp"}
	expiredChain := []*x509.Certificate{expiredLeaf, revokableTuples[1].Cert, revokableTuples[2].Cert}

	invalidChainErr := CheckOCSPError{Err: errors.New("invalid chain: expected chain to be correct and complete with each cert issued by the next in the chain")}
	chainRootErr := CheckOCSPError{Err: errors.New("invalid chain: expected chain to end with root cert")}
	expiredRespErr := CheckOCSPError{Err: errors.New("expired OCSP response")}

	r := NewRevocation(nil)

	t.Run("no OCSPServer specified", func(t *testing.T) {
		err := r.Validate(noOCSPChain)
		if err != nil {
			if _, ok := err.(NoOCSPServerError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected NoOCSPServerError")
		}
	})

	t.Run("chain missing root", func(t *testing.T) {
		err := r.Validate(noRootChain)
		if err != nil {
			if err.Error() != chainRootErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected chain root error")
		}
	})

	t.Run("backwards chain", func(t *testing.T) {
		err := r.Validate(backwardsChain)
		if err != nil {
			if err.Error() != invalidChainErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected chain root error")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		timeoutClient := &http.Client{Timeout: 1 * time.Nanosecond}
		timeoutR := NewRevocation(timeoutClient)
		err := timeoutR.Validate(okChain)
		if err != nil {
			if _, ok := err.(OCSPTimeoutError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected request to time out")
		}
	})

	t.Run("expired ocsp response", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil)
		expiredR := NewRevocation(client)
		err := expiredR.Validate(expiredChain)
		if err != nil {
			if err.Error() != expiredRespErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected expired response error")
		}
	})
}

func TestCheckRevocationInvalidChain(t *testing.T) {
	revokableTuples := testhelper.GetRevokableRSAChain(4)
	misorderedIntermediateTuples := []testhelper.RSACertTuple{revokableTuples[1], revokableTuples[0], revokableTuples[3]}
	misorderedIntermediateChain := []*x509.Certificate{revokableTuples[1].Cert, revokableTuples[0].Cert, revokableTuples[3].Cert}
	for i, cert := range misorderedIntermediateChain {
		if i != (len(misorderedIntermediateChain) - 1) {
			// Skip root which won't have an OCSP Server
			cert.OCSPServer[0] = fmt.Sprintf("http://localhost:8080/chain_ocsp/%d", i)
		}
	}

	missingIntermediateChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[2].Cert, revokableTuples[3].Cert}
	for i, cert := range missingIntermediateChain {
		if i != (len(misorderedIntermediateChain) - 1) {
			// Skip root which won't have an OCSP Server
			cert.OCSPServer[0] = fmt.Sprintf("http://localhost:8080/chain_ocsp/%d", i)
		}
	}

	invalidChainErr := CheckOCSPError{Err: errors.New("invalid chain: expected chain to be correct and complete with each cert issued by the next in the chain")}

	t.Run("chain missing intermediate", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil)
		r := NewRevocation(client)

		err := r.Validate(missingIntermediateChain)
		if err != nil {
			if err.Error() != invalidChainErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected invalid chain error")
		}
	})

	t.Run("chain out of order", func(t *testing.T) {
		client := testhelper.MockClient(misorderedIntermediateTuples, []ocsp.ResponseStatus{ocsp.Good}, nil)
		r := NewRevocation(client)

		err := r.Validate(misorderedIntermediateChain)
		if err != nil {
			if err.Error() != invalidChainErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected invalid chain error")
		}
	})
}

func TestSetMergeErrorsFunc(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	revokableChain := []*x509.Certificate{revokableCertTuple.Cert, revokableIssuerTuple.Cert}
	testChain := []testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}

	client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil)
	r := NewRevocation(client)

	err := r.Validate(revokableChain)
	if err != nil {
		t.Errorf("Unexpected error while checking revocation status: %v", err)
	}

	// After confirming that there shouldn't be an error, change only the merge function
	testErr := errors.New("test error returned by test merge function")
	r.SetMergeErrorsFunction(func(errors []error) error { return testErr })

	err = r.Validate(revokableChain)
	if err != nil {
		if err.Error() != testErr.Error() {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	} else {
		t.Errorf("Expected error from specified merge function")
	}

	// Confirm that it resolves when changed back
	r.SetMergeErrorsFunction(nil)

	err = r.Validate(revokableChain)
	if err != nil {
		t.Errorf("Unexpected error while checking revocation status: %v", err)
	}
}
