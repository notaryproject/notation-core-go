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

// Package result provides general objects that are used across revocation
package result

import (
	"fmt"
	"strconv"
	"time"
)

// Result is a type of enumerated value to help characterize errors. It can be
// OK, Unknown, or Revoked
type Result int

const (
	// ResultUnknown is a Result that indicates that some error other than a
	// revocation was encountered during the revocation check
	ResultUnknown Result = iota
	// ResultOK is a Result that indicates that the revocation check resulted in no
	// important errors
	ResultOK
	// ResultNonRevokable is a Result that indicates that the certificate cannot be
	// checked for revocation. This may be a result of no OCSP servers being
	// specified, the cert is a root certificate, or other related situations.
	ResultNonRevokable
	// ResultRevoked is a Result that indicates that at least one certificate was
	// revoked when performing a revocation check on the certificate chain
	ResultRevoked
)

// String provides a conversion from a Result to a string
func (r Result) String() string {
	switch r {
	case ResultOK:
		return "OK"
	case ResultNonRevokable:
		return "NonRevokable"
	case ResultUnknown:
		return "Unknown"
	case ResultRevoked:
		return "Revoked"
	default:
		return "invalid result with value " + strconv.Itoa(int(r))
	}
}

// ServerResult encapsulates the OCSP result for a single server for a single
// certificate in the chain
type ServerResult struct {
	// Result of revocation for this server (Unknown if there is an error which
	// prevents the retrieval of a valid status)
	Result Result

	// Server is the URI associated with this result. If no server is associated
	// with the result (e.g. it is a root certificate or no OCSPServers are
	// specified), then this will be an empty string ("")
	Server string

	// Error is set if there is an error associated with the revocation check
	// to this server
	Error error
}

// NewServerResult creates a ServerResult object from its individual parts: a
// Result, a string for the server, and an error
func NewServerResult(result Result, server string, err error) *ServerResult {
	return &ServerResult{
		Result: result,
		Server: server,
		Error:  err,
	}
}

// CRLReasonCode is CRL reason code (See RFC 5280, section 5.3.1)
type CRLReasonCode int

const (
	CRLReasonCodeUnspecified CRLReasonCode = iota
	CRLReasonCodeKeyCompromise
	CRLReasonCodeCACompromise
	CRLReasonCodeAffiliationChanged
	CRLReasonCodeSuperseded
	CRLReasonCodeCessationOfOperation
	CRLReasonCodeCertificateHold
	// value 7 is not used
	CRLReasonCodeRemoveFromCRL CRLReasonCode = iota + 1
	CRLReasonCodePrivilegeWithdrawn
	CRLReasonCodeAACompromise
)

// Equal checks if the reason code is equal to the given reason code
func (r CRLReasonCode) Equal(reasonCode int) bool {
	return int(r) == reasonCode
}

// String provides a conversion from a ReasonCode to a string
func (r CRLReasonCode) String() string {
	switch r {
	case CRLReasonCodeUnspecified:
		return "Unspecified"
	case CRLReasonCodeKeyCompromise:
		return "KeyCompromise"
	case CRLReasonCodeCACompromise:
		return "CACompromise"
	case CRLReasonCodeAffiliationChanged:
		return "AffiliationChanged"
	case CRLReasonCodeSuperseded:
		return "Superseded"
	case CRLReasonCodeCessationOfOperation:
		return "CessationOfOperation"
	case CRLReasonCodeCertificateHold:
		return "CertificateHold"
	case CRLReasonCodeRemoveFromCRL:
		return "RemoveFromCRL"
	case CRLReasonCodePrivilegeWithdrawn:
		return "PrivilegeWithdrawn"
	case CRLReasonCodeAACompromise:
		return "AACompromise"
	default:
		return fmt.Sprintf("invalid reason code with value: %d", r)
	}
}

// CRLResult encapsulates the result of a CRL check
type CRLResult struct {
	// ReasonCode is the reason code for the CRL status
	ReasonCode CRLReasonCode

	// RevocationTime is the time at which the certificate was revoked
	RevocationTime time.Time

	// Error is set if there is an error associated with the revocation check
	Error error
}

// CertRevocationResult encapsulates the result for a single certificate in the
// chain as well as the results from individual servers associated with this
// certificate
type CertRevocationResult struct {
	// Result of revocation for a specific cert in the chain
	//
	// If there are multiple ServerResults, this is because no responses were
	// able to be retrieved, leaving each ServerResult with a Result of Unknown.
	// Thus, in the case of more than one ServerResult, this will be ResultUnknown
	Result Result

	// An array of results for each server associated with the certificate.
	// The length will be either 1 or the number of OCSPServers for the cert.
	//
	// If the length is 1, then a valid status was able to be retrieved. Only
	// this server result is contained. Any errors for other servers are
	// discarded in favor of this valid response.
	//
	// Otherwise, every server specified had some error that prevented the
	// status from being retrieved. These are all contained here for evaluation
	ServerResults []*ServerResult

	// CRLResults is the result of the CRL check for this certificate
	CRLResults []*CRLResult

	// Error is set if there is an error associated with the revocation check
	Error error
}
