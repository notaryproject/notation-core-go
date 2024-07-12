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
	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
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

type Mode int

const (
	// ModeAutoFallback is the default mode that tries OCSP first and falls back
	// to CRL if OCSP doesn't exist or fails with unknown status
	ModeAutoFallback Mode = iota

	// ModeOCSPOnly is the mode that only uses OCSP for revocation checking
	ModeOCSPOnly

	// ModeCRLOnly is the mode that only uses CRL for revocation checking
	ModeCRLOnly
)

func (m Mode) CanRunOCSP() bool {
	return m == ModeAutoFallback || m == ModeOCSPOnly
}

func (m Mode) CanRunCRL() bool {
	return m == ModeAutoFallback || m == ModeCRLOnly
}

type Options struct {
	HttpClient       *http.Client
	Mode             Mode
	CertChainPurpose ocsp.Purpose
	CRLCache         cache.Cache
}

// revocation is an internal struct used for revocation checking
type revocation struct {
	mode       Mode
	httpClient *http.Client

	certChainPurpose ocsp.Purpose

	// crlCache caches the CRL files; the default one is memory cache
	crlCache cache.Cache
}

// New constructs a revocation object for code signing certificate chain
func New(httpClient *http.Client) (Revocation, error) {
	if httpClient == nil {
		return nil, errors.New("invalid input: a non-nil httpClient must be specified")
	}

	return &revocation{
		httpClient:       httpClient,
		certChainPurpose: ocsp.PurposeCodeSigning,
		crlCache:         cache.NewDummyCache(),
	}, nil
}

// NewTimestamp contructs a revocation object for timestamping certificate
// chain
func NewTimestamp(httpClient *http.Client) (Revocation, error) {
	if httpClient == nil {
		return nil, errors.New("invalid input: a non-nil httpClient must be specified")
	}
	return &revocation{
		httpClient:       httpClient,
		certChainPurpose: ocsp.PurposeTimestamping,
		crlCache:         cache.NewDummyCache(),
	}, nil
}

func NewWithOptions(opts Options) (Revocation, error) {
	if opts.HttpClient == nil {
		return nil, errors.New("invalid input: a non-nil httpClient must be specified")
	}

	switch opts.Mode {
	case ModeAutoFallback, ModeOCSPOnly, ModeCRLOnly:
	default:
		return nil, errors.New("invalid input: unknown mode")
	}

	switch opts.CertChainPurpose {
	case ocsp.PurposeCodeSigning, ocsp.PurposeTimestamping:
	default:
		return nil, errors.New("invalid input: unknown cert chain purpose")
	}

	if opts.CRLCache == nil {
		opts.CRLCache = cache.NewDummyCache()
	}

	return &revocation{
		mode:             opts.Mode,
		httpClient:       opts.HttpClient,
		certChainPurpose: opts.CertChainPurpose,
		crlCache:         opts.CRLCache,
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
		CertChain:        certChain,
		SigningTime:      signingTime,
		CertChainPurpose: r.certChainPurpose,
		HTTPClient:       r.httpClient,
	}

	crlOpts := crl.Options{
		CertChain:  certChain,
		HTTPClient: r.httpClient,
		Cache:      r.crlCache,
	}

	certResults := make([]*result.CertRevocationResult, len(certChain))
	var wg sync.WaitGroup
	for i, cert := range certChain[:len(certChain)-1] {
		switch {
		case r.mode.CanRunOCSP() && ocsp.HasOCSP(cert):
			// do OCSP check for the certificate
			wg.Add(1)

			// Assume cert chain is accurate and next cert in chain is the issuer
			go func(i int, cert *x509.Certificate) {
				defer wg.Done()
				certResults[i] = ocsp.CertCheckStatus(cert, certChain[i+1], ocspOpts)
			}(i, cert)
		case r.mode.CanRunCRL() && crl.HasCRL(cert):
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
