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
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/internal/crl"
	"github.com/notaryproject/notation-core-go/revocation/internal/ocsp"
	"github.com/notaryproject/notation-core-go/revocation/internal/x509util"
	ocspExternal "github.com/notaryproject/notation-core-go/revocation/ocsp"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	"github.com/notaryproject/notation-core-go/revocation/result"
)

// Revocation is an interface that specifies methods used for revocation checking.
//
// Deprecated: Revocation exists for backwards compatibility and should not be used.
// To perform revocation check, use [Validator].
type Revocation interface {
	// Validate checks the revocation status for a certificate chain using OCSP
	// and CRL if OCSP is not available. It returns an array of
	// CertRevocationResults that contain the results and any errors that are
	// encountered during the process
	Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*result.CertRevocationResult, error)
}

// ValidateContextOptions provides configuration options for revocation checks
type ValidateContextOptions struct {
	// CertChain denotes the certificate chain whose revocation status is
	// been validated. REQUIRED.
	CertChain []*x509.Certificate

	// AuthenticSigningTime denotes the authentic signing time of the signature.
	// It is used to compare with the InvalidityDate during revocation check.
	// OPTIONAL.
	//
	// Reference: https://github.com/notaryproject/specifications/blob/v1.0.0/specs/trust-store-trust-policy.md#revocation-checking-with-ocsp
	AuthenticSigningTime time.Time
}

// Validator is an interface that provides revocation checking with
// context
type Validator interface {
	// ValidateContext checks the revocation status given caller provided options
	// and returns an array of CertRevocationResults that contain the results
	// and any errors that are encountered during the process
	ValidateContext(ctx context.Context, validateContextOpts ValidateContextOptions) ([]*result.CertRevocationResult, error)
}

// revocation is an internal struct used for revocation checking
type revocation struct {
	ocspHTTPClient   *http.Client
	crlHTTPClient    *http.Client
	certChainPurpose purpose.Purpose
}

// New constructs a revocation object for code signing certificate chain.
//
// Deprecated: New exists for backwards compatibility and should not be used.
// To create a revocation object, use [NewWithOptions].
func New(httpClient *http.Client) (Revocation, error) {
	if httpClient == nil {
		return nil, errors.New("invalid input: a non-nil httpClient must be specified")
	}
	return &revocation{
		ocspHTTPClient:   httpClient,
		crlHTTPClient:    httpClient,
		certChainPurpose: purpose.CodeSigning,
	}, nil
}

// Options specifies values that are needed to check revocation
type Options struct {
	// OCSPHTTPClient is the HTTP client for OCSP request. If not provided,
	// a default *http.Client with timeout of 2 seconds will be used.
	// OPTIONAL.
	OCSPHTTPClient *http.Client

	// CRLHTTPClient is the HTTP client for CRL request. If not provided,
	// a default *http.Client with timeout of 5 seconds will be used.
	// OPTIONAL.
	CRLHTTPClient *http.Client

	// CertChainPurpose is the purpose of the certificate chain. Supported
	// values are CodeSigning and Timestamping. Default value is CodeSigning.
	// OPTIONAL.
	CertChainPurpose purpose.Purpose
}

// NewWithOptions constructs a Validator with the specified options
func NewWithOptions(opts Options) (Validator, error) {
	if opts.OCSPHTTPClient == nil {
		opts.OCSPHTTPClient = &http.Client{Timeout: 2 * time.Second}
	}

	if opts.CRLHTTPClient == nil {
		opts.CRLHTTPClient = &http.Client{Timeout: 5 * time.Second}
	}

	switch opts.CertChainPurpose {
	case purpose.CodeSigning, purpose.Timestamping:
	default:
		return nil, fmt.Errorf("unsupported certificate chain purpose %v", opts.CertChainPurpose)
	}

	return &revocation{
		ocspHTTPClient:   opts.OCSPHTTPClient,
		crlHTTPClient:    opts.CRLHTTPClient,
		certChainPurpose: opts.CertChainPurpose,
	}, nil
}

// Validate checks the revocation status for a certificate chain using OCSP.
// It returns an array of CertRevocationResults that contain the results and any
// errors that are encountered during the process.

// NOTE: The certificate chain is expected to be in the order of leaf to root.
func (r *revocation) Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*result.CertRevocationResult, error) {
	return ocspExternal.CheckStatus(ocspExternal.Options{
		CertChain:        certChain,
		CertChainPurpose: r.certChainPurpose,
		SigningTime:      signingTime,
		HTTPClient:       r.ocspHTTPClient,
	})
}

// ValidateContext checks the revocation status for a certificate chain using OCSP and
// CRL if OCSP is not available. It returns an array of CertRevocationResults
// that contain the results and any errors that are encountered during the
// process.
//
// This function tries OCSP and falls back to CRL when:
// - OCSP is not supported by the certificate
// - OCSP returns an unknown status
//
// NOTE: The certificate chain is expected to be in the order of leaf to root.
func (r *revocation) ValidateContext(ctx context.Context, validateContextOpts ValidateContextOptions) ([]*result.CertRevocationResult, error) {
	// validate certificate chain
	if len(validateContextOpts.CertChain) == 0 {
		return nil, result.InvalidChainError{Err: errors.New("chain does not contain any certificates")}
	}
	certChain := validateContextOpts.CertChain
	if err := x509util.ValidateChain(certChain, r.certChainPurpose); err != nil {
		return nil, err
	}

	ocspOpts := ocsp.CertCheckStatusOptions{
		HTTPClient:  r.ocspHTTPClient,
		SigningTime: validateContextOpts.AuthenticSigningTime,
	}
	crlOpts := crl.CertCheckStatusOptions{
		HTTPClient:  r.crlHTTPClient,
		SigningTime: validateContextOpts.AuthenticSigningTime,
	}

	// panicChain is used to store the panic in goroutine and handle it
	panicChan := make(chan any, len(certChain))
	defer close(panicChan)

	certResults := make([]*result.CertRevocationResult, len(certChain))
	var wg sync.WaitGroup
	for i, cert := range certChain[:len(certChain)-1] {
		switch {
		case ocsp.Supported(cert):
			// do OCSP check for the certificate
			wg.Add(1)

			go func(i int, cert *x509.Certificate) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						// catch panic and send it to panicChan to avoid
						// losing the panic
						panicChan <- r
					}
				}()

				// skip the error as it will never happen
				ocspResult := ocsp.CertCheckStatus(cert, certChain[i+1], ocspOpts)
				if ocspResult != nil && ocspResult.Result == result.ResultUnknown && crl.Supported(cert) {
					// try CRL check if OCSP result is unknown
					result := crl.CertCheckStatus(ctx, cert, certChain[i+1], crlOpts)

					// insert OCSP result into final result
					result.ServerResults = ocspResult.ServerResults
					certResults[i] = result
				} else {
					certResults[i] = ocspResult
				}
			}(i, cert)
		case crl.Supported(cert):
			// do CRL check for the certificate
			wg.Add(1)

			go func(i int, cert *x509.Certificate) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						// catch panic and send it to panicChan to avoid
						// losing the panic
						panicChan <- r
					}
				}()

				// skip the error as it will never happen
				certResults[i] = crl.CertCheckStatus(ctx, cert, certChain[i+1], crlOpts)
			}(i, cert)
		default:
			certResults[i] = &result.CertRevocationResult{
				Result: result.ResultNonRevokable,
			}
		}
	}

	// Last is root cert, which will never be revoked by OCSP or CRL
	certResults[len(certChain)-1] = &result.CertRevocationResult{
		Result: result.ResultNonRevokable,
	}
	wg.Wait()

	// handle panic
	select {
	case p := <-panicChan:
		panic(p)
	default:
	}

	return certResults, nil
}
