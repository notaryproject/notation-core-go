// Package Revocation provides methods for checking the revocation status of a certificate chain
package revocation

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/ocsp"
)

// Revocation is an interface that specifies methods used for revocation checking
type Revocation interface {
	Validate(certChain []*x509.Certificate, signingTime time.Time) error
	OCSPStatus(certChain []*x509.Certificate, signingTime time.Time) error
	SetMergeErrorsFunction(mergeErrorsFunc func(errors []error) error)
}

// revocation is an internal struct used for revocation checking
type revocation struct {
	httpClient      *http.Client
	logger          ocsp.Logger
	mergeErrorsFunc func(errors []error) error
}

// New constructs a revocation object and substitutes default values for any that are passed as nil
func New(httpClient *http.Client, logger ocsp.Logger) Revocation {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if logger == nil {
		logger = &ocsp.NoOpLogger{}
	}
	return &revocation{
		httpClient:      httpClient,
		logger:          logger,
		mergeErrorsFunc: DefaultMergeErrors,
	}
}

// Validate checks OCSP, returns nil if all certs in the chain are not revoked.
// If there is an error, it will return one of the errors defined in the revocation/ocsp package in errors.go.
// (e.g. if a certificate in the chain is revoked by OCSP and there are no other errors, it will return ocsp.RevokedError)
//
// TODO: add CRL support
func (r *revocation) Validate(certChain []*x509.Certificate, signingTime time.Time) error {
	return r.OCSPStatus(certChain, signingTime)
	// TODO: add CRL support
	// https://github.com/notaryproject/notation-core-go/issues/125
}

// OCSPStatus checks OCSP, returns nil if all certs in the chain are not revoked.
// If there is an error, it will return one of the errors defined in the revocation/ocsp package in errors.go.
// (e.g. if a certificate in the chain is revoked by OCSP and there are no other errors, it will return ocsp.RevokedError)
func (r *revocation) OCSPStatus(certChain []*x509.Certificate, signingTime time.Time) error {
	return ocsp.OCSPStatus(ocsp.Options{
		CertChain:       certChain,
		SigningTime:     signingTime,
		HTTPClient:      r.httpClient,
		MergeErrorsFunc: r.mergeErrorsFunc,
		Logger:          r.logger,
	})
}

// SetMergeErrorsFunction allows you to specify an alternative function to merge errors if the default does not fit your use case. You can also pass nil to reset it to the DefaultMergeErrors function
func (r *revocation) SetMergeErrorsFunction(mergeErrorsFunc func(errors []error) error) {
	if mergeErrorsFunc == nil {
		r.mergeErrorsFunc = DefaultMergeErrors
	} else {
		r.mergeErrorsFunc = mergeErrorsFunc
	}
}

// DefaultMergeErrors condenses errors for a list of errors (either for cert chain or OCSP servers) into one primary error
func DefaultMergeErrors(errorList []error) error {
	var result error
	if len(errorList) > 0 {
		result = errorList[0]

		for _, err := range errorList {
			if err == nil {
				continue
			}
			switch t := err.(type) {
			case ocsp.RevokedError:
				// There is a revoked certificate
				// return since any cert being revoked means leaf is revoked
				return t
			case ocsp.CheckOCSPError:
				// There is an error checking
				// return since any cert having error means chain has error (return earliest)
				return t
			case ocsp.UnknownStatusError:
				// A cert in the chain has status unknown
				// will not return immediately (in case one is revoked or has error), but will override other chain errors
				result = t
			case ocsp.NoOCSPServerError:
				// A cert in the chain does not have OCSP enabled
				// Still considered valid and not revoked
				// will not return immediately (in case there is higher level error)
				// will override OCSPTimeoutError and nil, but not UnknownInOCSPError (since a known unknown is worse than a cert without OCSP)
				if _, ok := result.(ocsp.UnknownStatusError); !ok || result == nil {
					result = t
				}
			case ocsp.TimeoutError:
				// A cert in the chain timed out while checking OCSP
				// will not return immediately (in case there is higher level error)
				// will override nil, but not UnknownInOCSPError or NoOCSPServerError (since timeout should only be conveyed if that is the only issue)
				if result == nil {
					result = t
				}
			default:
				return ocsp.CheckOCSPError{Err: err}
			}
		}

		return result
	} else {
		return nil
	}
}
