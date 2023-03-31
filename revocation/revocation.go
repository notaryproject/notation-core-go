// Package Revocation provides methods for checking the revocation status of a
// certificate chain
package revocation

import (
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/ocsp"
)

// Revocation is an interface that specifies methods used for revocation checking
type Revocation interface {
	// Validate checks the revocation status for a certificate chain using OCSP
	// and returns a 2D array of errors that are encountered during the process
	Validate(certChain []*x509.Certificate, signingTime time.Time) [][]error
}

// revocation is an internal struct used for revocation checking
type revocation struct {
	httpClient *http.Client
}

// New constructs a revocation object and substitutes default values for any
// that are passed as nil
func New(httpClient *http.Client) Revocation {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &revocation{
		httpClient: httpClient,
	}
}

// Validate checks the revocation status for a certificate chain using OCSP and
// returns a 2D array of errors that are encountered during the process
//
// The specific OCSP implementation is from the OCSPStatus function in the
// revocation/ocsp package.
//
// To get a single Result for the chain, pass the list of errors to the
// ResultFromErrors function
//
// TODO: add CRL support
// https://github.com/notaryproject/notation-core-go/issues/125
func (r *revocation) Validate(certChain []*x509.Certificate, signingTime time.Time) [][]error {
	return ocsp.OCSPStatus(ocsp.Options{
		CertChain:   certChain,
		SigningTime: signingTime,
		HTTPClient:  r.httpClient,
	})
	// TODO: add CRL support
	// https://github.com/notaryproject/notation-core-go/issues/125
}

// Result is a type of enumerated value to help characterize errors. It can be
// OK, Unknown, or Revoked
type Result int

const (
	// OK is a Result that indicates that the revocation check resulted in no
	// important errors
	OK Result = iota
	// Unknown is a Result that indicates that some error other than a
	// revocation was encountered during the revocation check
	Unknown
	// Revoked is a Result that indicates that at least one certificate was
	// revoked when performing a revocation check on the certificate chain
	Revoked
)

// String provides a conversion from a Result to a string
func (r Result) String() string {
	switch r {
	case OK:
		return "OK"
	case Unknown:
		return "Unknown"
	case Revoked:
		return "Revoked"
	default:
		return "Invalid Result"
	}
}

// ResultFromErrors provides a way to convert the [][]error result from
// Validate into a singular Result
func ResultFromErrors(errs [][]error) Result {
	currResult := OK
	for _, serverErrs := range errs {
		for _, err := range serverErrs {
			if err == nil || errors.Is(err, ocsp.NoOCSPServerError{}) {
				// These are OK, don't override Unknown or Revoked, continue
				continue
			} else if errors.Is(err, ocsp.RevokedError{}) {
				// If even one cert is revoked, then return Revoked
				return Revoked
			} else {
				// Includes ocsp.CheckOCSPError, ocsp.UnknownStatusError,
				// ocsp.PKIXNoCheckError, and ocsp.TimeoutError
				// Overrides OK, but continues in case a cert is revoked
				currResult = Unknown
			}
		}
	}

	return currResult
}
