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

// Package ocsp provides methods for checking the OCSP revocation status of a
// certificate chain, as well as errors related to these checks
package ocsp

import (
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/internal/chain"
	"github.com/notaryproject/notation-core-go/revocation/internal/ocsp"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	"github.com/notaryproject/notation-core-go/revocation/result"
)

// Options specifies values that are needed to check OCSP revocation
type Options struct {
	CertChain []*x509.Certificate

	// CertChainPurpose is the purpose of the certificate chain. Supported
	// values are CodeSigning and Timestamping.
	// When not provided, the default value is CodeSigning.
	CertChainPurpose purpose.Purpose
	SigningTime      time.Time
	HTTPClient       *http.Client
}

// CheckStatus checks OCSP based on the passed options and returns an array of
// result.CertRevocationResult objects that contains the results and error. The
// length of this array will always be equal to the length of the certificate
// chain.
func CheckStatus(opts Options) ([]*result.CertRevocationResult, error) {
	if len(opts.CertChain) == 0 {
		return nil, result.InvalidChainError{Err: errors.New("chain does not contain any certificates")}
	}

	if err := chain.Validate(opts.CertChain, opts.CertChainPurpose); err != nil {
		return nil, err
	}

	certResults := make([]*result.CertRevocationResult, len(opts.CertChain))

	// Check status for each cert in cert chain
	var wg sync.WaitGroup
	for i, cert := range opts.CertChain[:len(opts.CertChain)-1] {
		wg.Add(1)
		// Assume cert chain is accurate and next cert in chain is the issuer
		go func(i int, cert *x509.Certificate) {
			defer wg.Done()
			certResults[i] = ocsp.CertCheckStatus(cert, opts.CertChain[i+1], ocsp.Options{
				SigningTime: opts.SigningTime,
				HTTPClient:  opts.HTTPClient,
			})
		}(i, cert)
	}
	// Last is root cert, which will never be revoked by OCSP
	certResults[len(opts.CertChain)-1] = &result.CertRevocationResult{
		Result: result.ResultNonRevokable,
		ServerResults: []*result.ServerResult{{
			Result: result.ResultNonRevokable,
			Error:  nil,
		}},
	}

	wg.Wait()
	return certResults, nil
}
