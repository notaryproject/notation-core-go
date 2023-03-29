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

func defaultMergeErrors(errorList []error) error {
	var result error
	if len(errorList) > 0 {
		result = errorList[0]

		for _, err := range errorList {
			if err == nil {
				continue
			}
			switch t := err.(type) {
			case RevokedError:
				return t
			case CheckOCSPError:
				return t
			case UnknownStatusError:
				result = t
			case PKIXNoCheckError:
				if _, ok := result.(UnknownStatusError); !ok || result == nil {
					result = t
				}
			case TimeoutError:
				if _, ok := result.(NoOCSPServerError); ok || result == nil {
					result = t
				}
			case NoOCSPServerError:
				if result == nil {
					result = t
				}
			default:
				return CheckOCSPError{Err: err}
			}
		}

		return result
	} else {
		return nil
	}
}

func TestCheckOCSPStatusForSingleCert(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableIssuerTuple := testhelper.GetRSARootCertificate()
	revokableChain := []*x509.Certificate{revokableCertTuple.Cert, revokableIssuerTuple.Cert}
	testChain := []testhelper.RSACertTuple{revokableCertTuple, revokableIssuerTuple}

	t.Run("check non-revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Unknown}, nil, true)
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(UnknownStatusError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, nil, true)
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(RevokedError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Revoked}, &revokedTime, true)
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
}

func TestCheckOCSPStatusForSelfSignedCert(t *testing.T) {
	selfSignedTuple := testhelper.GetRSASelfSignedSigningCertTuple("Notation revocation test self-signed cert")
	client := testhelper.MockClient([]testhelper.RSACertTuple{selfSignedTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	opts := Options{
		CertChain:       []*x509.Certificate{selfSignedTuple.Cert},
		SigningTime:     time.Now(),
		HTTPClient:      client,
		MergeErrorsFunc: defaultMergeErrors,
	}

	chainRootErr := CheckOCSPError{Err: errors.New("invalid chain: expected chain to end with root cert")}
	err := OCSPStatus(opts)
	if err != nil {
		if err.Error() != chainRootErr.Error() {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	} else {
		t.Errorf("Expected chain root error")
	}
}

func TestCheckOCSPStatusForRootCert(t *testing.T) {
	rootTuple := testhelper.GetRSARootCertificate()
	client := testhelper.MockClient([]testhelper.RSACertTuple{rootTuple}, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
	opts := Options{
		CertChain:       []*x509.Certificate{rootTuple.Cert},
		SigningTime:     time.Now(),
		HTTPClient:      client,
		MergeErrorsFunc: defaultMergeErrors,
	}

	err := OCSPStatus(opts)
	if err != nil {
		t.Errorf("Unexpected error while checking revocation status: %v", err)
	}
}

func TestCheckOCSPStatusForChain(t *testing.T) {
	testChain := testhelper.GetRevokableRSAChain(6)
	revokableChain := make([]*x509.Certificate, 6)
	for i, tuple := range testChain {
		revokableChain[i] = tuple.Cert
	}

	t.Run("empty chain", func(t *testing.T) {
		opts := Options{
			CertChain:       []*x509.Certificate{},
			SigningTime:     time.Now(),
			HTTPClient:      http.DefaultClient,
			MergeErrorsFunc: defaultMergeErrors,
		}
		err := OCSPStatus(opts)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
	t.Run("check non-revoked chain", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
	t.Run("check chain with 1 Unknown cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, the rest will be good
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(UnknownStatusError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP with 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(RevokedError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP with 1 unknown and 1 revoked cert", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(RevokedError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP with 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be revoked, the rest will be good
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
	})
	t.Run("check OCSP with 1 unknown and 1 future revoked cert", func(t *testing.T) {
		revokedTime := time.Now().Add(time.Hour)
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Unknown, ocsp.Good, ocsp.Revoked, ocsp.Good}, &revokedTime, true)
		// 3rd cert will be unknown, 5th will be revoked, the rest will be good
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(UnknownStatusError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
	t.Run("check OCSP with 1 revoked cert after signing time", func(t *testing.T) {
		client := testhelper.MockClient(testChain, []ocsp.ResponseStatus{ocsp.Good, ocsp.Good, ocsp.Revoked, ocsp.Good}, nil, true)
		// 3rd cert will be revoked, the rest will be good
		opts := Options{
			CertChain:       revokableChain,
			SigningTime:     time.Now().Add(-2 * time.Hour),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(RevokedError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected certificate to be revoked")
		}
	})
}

func TestCheckOCSPErrors(t *testing.T) {
	leafCertTuple := testhelper.GetRSALeafCertificate()
	rootCertTuple := testhelper.GetRSARootCertificate()
	noOCSPChain := []*x509.Certificate{leafCertTuple.Cert, rootCertTuple.Cert}

	revokableTuples := testhelper.GetRevokableRSAChain(3)
	noRootChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert}
	backwardsChain := []*x509.Certificate{revokableTuples[2].Cert, revokableTuples[1].Cert, revokableTuples[0].Cert}
	okChain := []*x509.Certificate{revokableTuples[0].Cert, revokableTuples[1].Cert, revokableTuples[2].Cert}

	expiredLeaf, _ := x509.ParseCertificate(revokableTuples[0].Cert.Raw)
	expiredLeaf.OCSPServer = []string{"http://localhost:8080/expired_ocsp"}
	expiredChain := []*x509.Certificate{expiredLeaf, revokableTuples[1].Cert, revokableTuples[2].Cert}

	invalidChainErr := CheckOCSPError{Err: errors.New("invalid chain: expected chain to be correct and complete with each cert issued by the next in the chain")}
	chainRootErr := CheckOCSPError{Err: errors.New("invalid chain: expected chain to end with root cert")}
	expiredRespErr := CheckOCSPError{Err: errors.New("expired OCSP response")}

	t.Run("no OCSPServer specified", func(t *testing.T) {
		opts := Options{
			CertChain:       noOCSPChain,
			SigningTime:     time.Now(),
			HTTPClient:      http.DefaultClient,
			MergeErrorsFunc: defaultMergeErrors,
		}
		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(NoOCSPServerError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected NoOCSPServerError")
		}
	})

	t.Run("chain missing root", func(t *testing.T) {
		opts := Options{
			CertChain:       noRootChain,
			SigningTime:     time.Now(),
			HTTPClient:      http.DefaultClient,
			MergeErrorsFunc: defaultMergeErrors,
		}
		err := OCSPStatus(opts)
		if err != nil {
			if err.Error() != chainRootErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected chain root error")
		}
	})

	t.Run("backwards chain", func(t *testing.T) {
		opts := Options{
			CertChain:       backwardsChain,
			SigningTime:     time.Now(),
			HTTPClient:      http.DefaultClient,
			MergeErrorsFunc: defaultMergeErrors,
		}
		err := OCSPStatus(opts)
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
		opts := Options{
			CertChain:       okChain,
			SigningTime:     time.Now(),
			HTTPClient:      timeoutClient,
			MergeErrorsFunc: defaultMergeErrors,
		}
		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(TimeoutError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected request to time out")
		}
	})

	t.Run("expired ocsp response", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:       expiredChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}
		err := OCSPStatus(opts)
		if err != nil {
			if err.Error() != expiredRespErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected expired response error")
		}
	})

	t.Run("pkixNoCheck error", func(t *testing.T) {
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, false)
		opts := Options{
			CertChain:       okChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}

		err := OCSPStatus(opts)
		if err != nil {
			if _, ok := err.(PKIXNoCheckError); !ok {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected chain to have PKIXNoCheckError")
		}
	})
}

func TestCheckOCSPInvalidChain(t *testing.T) {
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
		client := testhelper.MockClient(revokableTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:       missingIntermediateChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}
		err := OCSPStatus(opts)
		if err != nil {
			if err.Error() != invalidChainErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected invalid chain error")
		}
	})

	t.Run("chain out of order", func(t *testing.T) {
		client := testhelper.MockClient(misorderedIntermediateTuples, []ocsp.ResponseStatus{ocsp.Good}, nil, true)
		opts := Options{
			CertChain:       misorderedIntermediateChain,
			SigningTime:     time.Now(),
			HTTPClient:      client,
			MergeErrorsFunc: defaultMergeErrors,
		}
		err := OCSPStatus(opts)
		if err != nil {
			if err.Error() != invalidChainErr.Error() {
				t.Errorf("Unexpected error while checking revocation status: %v", err)
			}
		} else {
			t.Errorf("Expected invalid chain error")
		}
	})
}
