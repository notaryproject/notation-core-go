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
	Validate(certChain []*x509.Certificate, signingTime time.Time) []*CertRevocationResult
}

// revocation is an internal struct used for revocation checking
type revocation struct {
	httpClient *http.Client
}

// New constructs a revocation object
func New(httpClient *http.Client) (Revocation, error) {
	if httpClient == nil {
		return nil, errors.New("invalid input: a non-nil httpClient must be specified")
	}
	return &revocation{
		httpClient: httpClient,
	}, nil
}

// Validate checks the revocation status for a certificate chain using OCSP and
// returns a 2D array of errors that are encountered during the process
//
// The specific OCSP implementation is from the CheckStatus function in the
// revocation/ocsp package.
//
// To get a single Result for the chain, pass the list of errors to the
// ResultFromErrors function
//
// TODO: add CRL support
// https://github.com/notaryproject/notation-core-go/issues/125
func (r *revocation) Validate(certChain []*x509.Certificate, signingTime time.Time) []*CertRevocationResult {
	ocspErrs := ocsp.CheckStatus(ocsp.Options{
		CertChain:   certChain,
		SigningTime: signingTime,
		HTTPClient:  r.httpClient,
	})
	return ocspErrsToRevocationOutcome(ocspErrs)
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

// ServerResult encapsulates the result for a single server for a single
// certificate in the chain
type ServerResult struct {
	// Result of revocation for this server (Unknown if there is an error which
	// prevents the retrieval of a valid status)
	Result Result

	// Error is set if there is an error associated with the revocation check
	// to this server
	Error error
}

// CertRevocationResult encapsulates the result for a single certificate in the
// chain as well as the results from individual servers associated with this
// certificate
type CertRevocationResult struct {
	// Result of revocation for a specific cert in the chain
	Result Result

	// An array of results for each server assocaited with the certificate.
	// The length will be either 1 or the number of OCSPServers for the cert.
	//
	// If the length is 1, then a valid status was able to be retrieved. Only
	// this server result is contained. Any errors for other servers are
	// discarded in favor of this valid response.
	//
	// Otherwise, every server specified had some error that prevented the
	// status from being retrieved. These are all contained here for evaluation
	ServerResults []*ServerResult
}

func errToServerResult(err error) *ServerResult {
	if err == nil || errors.Is(err, ocsp.NoOCSPServerError{}) {
		return &ServerResult{
			Result: OK,
			Error:  err,
		}
	} else if errors.Is(err, ocsp.RevokedError{}) {
		return &ServerResult{
			Result: Revoked,
			Error:  err,
		}
	}
	// Includes ocsp.OCSPCheckError, ocsp.UnknownStatusError
	// ocsp.PKIXNoCheckError, InvalidChainError, and ocsp.TimeoutError
	return &ServerResult{
		Result: Unknown,
		Error:  err,
	}
}

func serverErrsToCertRevocationResult(serverErrs []error) *CertRevocationResult {
	if len(serverErrs) == 1 {
		serverRes := errToServerResult(serverErrs[0])
		return &CertRevocationResult{
			Result:        serverRes.Result,
			ServerResults: []*ServerResult{serverRes},
		}
	}
	serverResults := make([]*ServerResult, len(serverErrs))
	currResult := OK
	for j, err := range serverErrs {
		serverRes := errToServerResult(err)
		serverResults[j] = serverRes
		switch serverRes.Result {
		case Revoked:
			currResult = Revoked
		case Unknown:
			if currResult != Revoked {
				currResult = Unknown
			}
		}
	}
	return &CertRevocationResult{
		Result:        currResult,
		ServerResults: serverResults,
	}
}

func ocspErrsToRevocationOutcome(ocspErrs [][]error) []*CertRevocationResult {
	certResults := make([]*CertRevocationResult, len(ocspErrs))
	for i, serverErrs := range ocspErrs {
		certResults[i] = serverErrsToCertRevocationResult(serverErrs)
	}

	return certResults
}
