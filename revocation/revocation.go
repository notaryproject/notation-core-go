// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package Revocation provides methods for checking the revocation status of a
// certificate chain
package revocation

import (
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/ocsp"
	"github.com/notaryproject/notation-core-go/revocation/result"
)

// Revocation is an interface that specifies methods used for revocation checking
type Revocation interface {
	// Validate checks the revocation status for a certificate chain using OCSP
	// and returns an array of CertRevocationResults that contain the results
	// and any errors that are encountered during the process
	Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*result.CertRevocationResult, error)
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
func (r *revocation) Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*result.CertRevocationResult, error) {
	return ocsp.CheckStatus(ocsp.Options{
		CertChain:   certChain,
		SigningTime: signingTime,
		HTTPClient:  r.httpClient,
	})
	// TODO: add CRL support
	// https://github.com/notaryproject/notation-core-go/issues/125
}

// ValidateTimestampCertChain checks the revocation status for a TSA certificate
// chain using OCSP and returns an array of CertRevocationResults that contain
// the results and any errors that are encountered during the process
//
// TODO: add CRL support
// https://github.com/notaryproject/notation-core-go/issues/125
func ValidateTimestampCertChain(certChain []*x509.Certificate, signingTime time.Time, httpClient *http.Client) ([]*result.CertRevocationResult, error) {
	return ocsp.CheckStatus(ocsp.Options{
		CertChain:   certChain,
		Timestamp:   true,
		SigningTime: signingTime,
		HTTPClient:  httpClient,
	})
	// TODO: add CRL support
	// https://github.com/notaryproject/notation-core-go/issues/125
}
