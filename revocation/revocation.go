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
	"fmt"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/ocsp"
	"github.com/notaryproject/notation-core-go/revocation/result"
	revX509 "github.com/notaryproject/notation-core-go/revocation/x509"
)

// Revocation is an interface that specifies methods used for revocation checking
type Revocation interface {
	// Validate checks the revocation status for a certificate chain using OCSP
	// and returns an array of CertRevocationResults that contain the results
	// and any errors that are encountered during the process
	Validate(certChain []*x509.Certificate, signingTime time.Time) ([]*result.CertRevocationResult, error)
}

// Options specifies values that are needed to check revocation
type Options struct {
	// OCSPHTTPClient is a required HTTP client for OCSP request
	OCSPHTTPClient *http.Client

	// CertChainPurpose is the purpose of the certificate chain
	CertChainPurpose revX509.Purpose
}

// revocation is an internal struct used for revocation checking
type revocation struct {
	httpClient       *http.Client
	certChainPurpose revX509.Purpose
}

// New constructs a revocation object for code signing certificate chain
func New(httpClient *http.Client) (Revocation, error) {
	if httpClient == nil {
		return nil, errors.New("invalid input: a non-nil httpClient must be specified")
	}
	return &revocation{
		httpClient:       httpClient,
		certChainPurpose: revX509.PurposeCodeSigning,
	}, nil
}

// NewWithOptions constructs a revocation object with the specified options
func NewWithOptions(opts *Options) (Revocation, error) {
	if opts.OCSPHTTPClient == nil {
		return nil, errors.New("invalid input: a non-nil OCSPHTTPClient must be specified")
	}

	switch opts.CertChainPurpose {
	case revX509.PurposeCodeSigning, revX509.PurposeTimestamping:
	default:
		return nil, fmt.Errorf("unknown certificate chain purpose %v", opts.CertChainPurpose)
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
	return ocsp.CheckStatus(ocsp.Options{
		CertChain:        certChain,
		CertChainPurpose: r.certChainPurpose,
		SigningTime:      signingTime,
		HTTPClient:       r.httpClient,
	})

	// TODO: add CRL support
	// https://github.com/notaryproject/notation-core-go/issues/125
}
