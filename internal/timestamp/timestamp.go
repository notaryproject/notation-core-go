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

// Package timestamp provides functionalities of timestamp countersignature
package timestamp

import (
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/signature"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/tspclient-go"
)

// Timestamp generates a timestamp request and sends to TSA. It then validates
// the TSA certificate chain against Notary Project certificate and signature
// algorithm requirements.
// On success, it returns the full bytes of the timestamp token received from
// TSA.
//
// Reference: https://github.com/notaryproject/specifications/blob/v1.0.0/specs/signature-specification.md#leaf-certificates
func Timestamp(req *signature.SignRequest, opts tspclient.RequestOptions) ([]byte, error) {
	tsaRequest, err := tspclient.NewRequest(opts)
	if err != nil {
		return nil, err
	}
	ctx := req.Context()
	resp, err := req.Timestamper.Timestamp(ctx, tsaRequest)
	if err != nil {
		return nil, err
	}
	token, err := resp.SignedToken()
	if err != nil {
		return nil, err
	}
	tsaCertChain, err := token.Verify(ctx, x509.VerifyOptions{
		Roots: req.TSARootCAs,
	})
	if err != nil {
		return nil, err
	}
	if err := nx509.ValidateTimestampingCertChain(tsaCertChain); err != nil {
		return nil, err
	}
	// certificate chain revocation check after timestamping
	if req.TSARevocationValidator != nil {
		certResults, err := req.TSARevocationValidator.ValidateContext(ctx, revocation.ValidateContextOptions{
			CertChain: tsaCertChain,
		})
		if err != nil {
			return nil, fmt.Errorf("after timestamping: failed to check timestamping certificate chain revocation with error: %w", err)
		}
		if err := revocationFinalResult(certResults, tsaCertChain); err != nil {
			return nil, fmt.Errorf("after timestamping: %w", err)
		}
	}
	return resp.TimestampToken.FullBytes, nil
}

// revocationFinalResult returns an error if the final revocation result is
// not ResultOK
func revocationFinalResult(certResults []*result.CertRevocationResult, certChain []*x509.Certificate) error {
	finalResult := result.ResultUnknown
	numOKResults := 0
	var problematicCertSubject string
	revokedFound := false
	var revokedCertSubject string
	for i := len(certResults) - 1; i >= 0; i-- {
		cert := certChain[i]
		certResult := certResults[i]
		if certResult.Result == result.ResultOK || certResult.Result == result.ResultNonRevokable {
			numOKResults++
		} else {
			finalResult = certResult.Result
			problematicCertSubject = cert.Subject.String()
			if certResult.Result == result.ResultRevoked {
				revokedFound = true
				revokedCertSubject = problematicCertSubject
			}
		}
	}
	if revokedFound {
		problematicCertSubject = revokedCertSubject
		finalResult = result.ResultRevoked
	}
	if numOKResults == len(certResults) {
		finalResult = result.ResultOK
	}

	// process final result
	switch finalResult {
	case result.ResultOK:
		return nil
	case result.ResultRevoked:
		return fmt.Errorf("timestamping certificate with subject %q is revoked", problematicCertSubject)
	default:
		// revocationresult.ResultUnknown
		return fmt.Errorf("timestamping certificate with subject %q revocation status is unknown", problematicCertSubject)
	}
}
