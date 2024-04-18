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
	"sync"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-core-go/revocation/ocsp"
	"github.com/notaryproject/notation-core-go/revocation/result"
	coreX509 "github.com/notaryproject/notation-core-go/x509"
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

	// CRLCache caches the CRL files, the default one is memory cache
	CRLCache crl.Cache
}

// New constructs a revocation object
func New(httpClient *http.Client) (Revocation, error) {
	if httpClient == nil {
		return nil, errors.New("invalid input: a non-nil httpClient must be specified")
	}

	return &revocation{
		httpClient: httpClient,
		CRLCache:   crl.NewMemoryCache(),
	}, nil
}

// Validate checks the revocation status for a certificate chain using OCSP or
// CRL and returns an array of CertRevocationResults that contain the results
// and any errors that are encountered during the process
func (r *revocation) Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*result.CertRevocationResult, error) {
	if len(certChain) == 0 {
		return nil, result.InvalidChainError{Err: errors.New("chain does not contain any certificates")}
	}

	if err := coreX509.ValidateCodeSigningCertChain(certChain, nil); err != nil {
		return nil, result.InvalidChainError{Err: err}
	}

	ocspOpts := ocsp.Options{
		CertChain:   certChain,
		SigningTime: signingTime,
		HTTPClient:  r.httpClient,
	}

	crlOpts := crl.Options{
		CertChain:  certChain,
		HTTPClient: r.httpClient,
		Cache:      r.CRLCache,
	}

	certResults := make([]*result.CertRevocationResult, len(certChain))
	var wg sync.WaitGroup
	for i, cert := range certChain[:len(certChain)-1] {
		switch {
		case ocsp.HasOCSP(cert):
			// do OCSP check for the certificate
			wg.Add(1)

			// Assume cert chain is accurate and next cert in chain is the issuer
			go func(i int, cert *x509.Certificate) {
				defer wg.Done()
				certResults[i] = ocsp.CertCheckStatus(cert, certChain[i+1], ocspOpts)
			}(i, cert)
		case crl.HasCRL(cert):
			// do CRL check for the certificate
			wg.Add(1)

			go func(i int, cert *x509.Certificate) {
				defer wg.Done()

				certResults[i] = crl.CertCheckStatus(cert, certChain[i+1], crlOpts)
			}(i, cert)
		default:
			certResults[i] = &result.CertRevocationResult{
				Result: result.ResultNonRevokable,
				ServerResults: []*result.ServerResult{{
					Result: result.ResultNonRevokable,
					Error:  nil,
				}},
			}
		}
	}

	// Last is root cert, which will never be revoked by OCSP
	certResults[len(certChain)-1] = &result.CertRevocationResult{
		Result: result.ResultNonRevokable,
		ServerResults: []*result.ServerResult{{
			Result: result.ResultNonRevokable,
			Error:  nil,
		}},
	}
	wg.Wait()
	return certResults, nil
}
