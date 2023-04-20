// Package result provides general objects that are used across revocation
package result

import "strconv"

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

// ServerResult encapsulates the result for a single server for a single
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
}
