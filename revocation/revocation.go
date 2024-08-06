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
	"time"

	"github.com/notaryproject/notation-core-go/revocation/ocsp"
	"github.com/notaryproject/notation-core-go/revocation/result"
)

// Revocation is an interface that specifies methods used for revocation checking.
//
// Deprecated: Revocation exists for backwards compatibility and should not be used.
// To perform revocation check, use [Validator].
type Revocation interface {
	// Validate checks the revocation status for a certificate chain using OCSP
	// and returns an array of CertRevocationResults that contain the results
	// and any errors that are encountered during the process
	Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*result.CertRevocationResult, error)
}

// ValidateContextOptions provides configuration options for revocation checks
type ValidateContextOptions struct {
	// CertChain denotes the certificate chain whose revocation status is
	// been validated. REQUIRED.
	CertChain []*x509.Certificate

	// AuthenticSigningTime denotes the authentic signing time of the signature.
	// It is solely used under signing scheme notary.x509.signingAuthority.
	// OPTIONAL.
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
	httpClient       *http.Client
	certChainPurpose x509.ExtKeyUsage
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
		httpClient:       httpClient,
		certChainPurpose: x509.ExtKeyUsageCodeSigning,
	}, nil
}

// Options specifies values that are needed to check revocation
type Options struct {
	// OCSPHTTPClient is the HTTP client for OCSP request. If not provided,
	// a default *http.Client with timeout of 2 seconds will be used.
	// OPTIONAL.
	OCSPHTTPClient *http.Client

	// CertChainPurpose is the purpose of the certificate chain. Supported
	// values are x509.ExtKeyUsageCodeSigning and x509.ExtKeyUsageTimeStamping.
	// REQUIRED.
	CertChainPurpose x509.ExtKeyUsage
}

// NewWithOptions constructs a Validator with the specified options
func NewWithOptions(opts Options) (Validator, error) {
	if opts.OCSPHTTPClient == nil {
		opts.OCSPHTTPClient = &http.Client{Timeout: 2 * time.Second}
	}

	switch opts.CertChainPurpose {
	case x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping:
	default:
		return nil, fmt.Errorf("unsupported certificate chain purpose %v", opts.CertChainPurpose)
	}

	return &revocation{
		httpClient:       opts.OCSPHTTPClient,
		certChainPurpose: opts.CertChainPurpose,
	}, nil
}

// Validate checks the revocation status for a certificate chain using OCSP and
// returns an array of CertRevocationResults that contain the results and any
// errors that are encountered during the process
//
// TODO: add CRL support
// https://github.com/notaryproject/notation-core-go/issues/125
func (r *revocation) Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*result.CertRevocationResult, error) {
	return r.ValidateContext(context.Background(), ValidateContextOptions{
		CertChain:            certChain,
		AuthenticSigningTime: signingTime,
	})
}

// ValidateContext checks the revocation status for a certificate chain using
// OCSP and returns an array of CertRevocationResults that contain the results
// and any errors that are encountered during the process
//
// TODO: add CRL support
// https://github.com/notaryproject/notation-core-go/issues/125
func (r *revocation) ValidateContext(ctx context.Context, validateContextOpts ValidateContextOptions) ([]*result.CertRevocationResult, error) {
	if len(validateContextOpts.CertChain) == 0 {
		return nil, result.InvalidChainError{Err: errors.New("chain does not contain any certificates")}
	}

	return ocsp.CheckStatus(ocsp.Options{
		CertChain:        validateContextOpts.CertChain,
		CertChainPurpose: r.certChainPurpose,
		SigningTime:      validateContextOpts.AuthenticSigningTime,
		HTTPClient:       r.httpClient,
	})

	// TODO: add CRL support
	// https://github.com/notaryproject/notation-core-go/issues/125
}
