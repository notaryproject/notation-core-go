// Package Revocation provides methods for checking the revocation status of a
// certificate chain
package revocation

import (
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/base"
	"github.com/notaryproject/notation-core-go/revocation/ocsp"
)

// Revocation is an interface that specifies methods used for revocation checking
type Revocation interface {
	// Validate checks the revocation status for a certificate chain using OCSP
	// and returns an array of CertRevocationResults that contain the results
	// and any errors that are encountered during the process
	Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*base.CertRevocationResult, error)
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
// returns an array of CertRevocationResults that contain the results and any
// errors that are encountered during the process
//
// TODO: add CRL support
// https://github.com/notaryproject/notation-core-go/issues/125
func (r *revocation) Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*base.CertRevocationResult, error) {
	return ocsp.CheckStatus(ocsp.Options{
		CertChain:   certChain,
		SigningTime: signingTime,
		HTTPClient:  r.httpClient,
	})
	// TODO: add CRL support
	// https://github.com/notaryproject/notation-core-go/issues/125
}
