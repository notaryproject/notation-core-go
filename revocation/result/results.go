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

import "strconv"

// Result is a type of enumerated value to help characterize revocation result.
// It can be OK, Unknown, NonRevokable, or Revoked
type Result int

const (
	// ResultUnknown is a Result that indicates that some error other than a
	// revocation was encountered during the revocation check.
	ResultUnknown Result = iota

	// ResultOK is a Result that indicates that the revocation check resulted in
	// no important errors.
	ResultOK

	// ResultNonRevokable is a Result that indicates that the certificate cannot
	// be checked for revocation. This may be due to the absence of OCSP servers
	// or CRL distribution points, or because the certificate is a root
	// certificate.
	ResultNonRevokable

	// ResultRevoked is a Result that indicates that at least one certificate was
	// revoked when performing a revocation check on the certificate chain.
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

// RevocationMethod defines the method used to check the revocation status of a
// certificate.
type RevocationMethod int

const (
	// RevocationMethodUnknown is used for root certificates or when the method
	// used to check the revocation status of a certificate is unknown.
	RevocationMethodUnknown RevocationMethod = iota

	// RevocationMethodOCSP represents OCSP as the method used to check the
	// revocation status of a certificate.
	RevocationMethodOCSP

	// RevocationMethodCRL represents CRL as the method used to check the
	// revocation status of a certificate.
	RevocationMethodCRL

	// RevocationMethodOCSPFallbackCRL represents OCSP check with unknown error
	// fallback to CRL as the method used to check the revocation status of a
	// certificate.
	RevocationMethodOCSPFallbackCRL
)

// String provides a conversion from a Method to a string
func (m RevocationMethod) String() string {
	switch m {
	case RevocationMethodOCSP:
		return "OCSP"
	case RevocationMethodCRL:
		return "CRL"
	case RevocationMethodOCSPFallbackCRL:
		return "OCSPFallbackCRL"
	default:
		return "Unknown"
	}
}

// ServerResult encapsulates the OCSP result for a single server or the CRL
// result for a single CRL URI for a certificate in the chain
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

	// RevocationMethod is the method used to check the revocation status of the
	// certificate, including MethodUnknown, MethodOCSP, MethodCRL
	RevocationMethod RevocationMethod
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

// CertRevocationResult encapsulates the result for a single certificate in the
// chain as well as the results from individual servers associated with this
// certificate
type CertRevocationResult struct {
	// Result of revocation for a specific certificate in the chain.
	Result Result

	// ServerResults is an array of results for each server associated with the
	// certificate.
	//
	// When RevocationMethod is MethodOCSP, the length will be
	// either 1 or the number of OCSPServers for the certificate.
	// If the length is 1, then a valid status was retrieved. Only
	// this server result is contained. Any errors for other servers are
	// discarded in favor of this valid response.
	// Otherwise, every server specified had some error that prevented the
	// status from being retrieved. These are all contained here for evaluation.
	//
	// When RevocationMethod is MethodCRL, the length will be the number of
	// CRL distribution points' URIs checked. If the result is Revoked, or
	// there is an error, the length will be 1.
	//
	// When RevocationMethod is MethodOCSPFallbackCRL, the length
	// will be the sum of the previous two cases. The CRL result will be
	// appended after the OCSP results.
	ServerResults []*ServerResult

	// RevocationMethod is the method used to check the revocation status of the
	// certificate, including MethodUnknown, MethodOCSP, MethodCRL and
	// MethodOCSPFallbackCRL
	RevocationMethod RevocationMethod
}
