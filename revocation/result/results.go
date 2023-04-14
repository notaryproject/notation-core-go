// Package result provides general objects that are used across revocation
package result

import "strconv"

// Result is a type of enumerated value to help characterize errors. It can be
// OK, Unknown, or Revoked
type Result int

const (
	// ResultOK is a Result that indicates that the revocation check resulted in no
	// important errors
	ResultOK Result = 1 + iota
	// ResultNonRevokable is a Result that indicates that the certificate cannot be
	// checked for revocation. This may be a result of no OCSP servers being
	// specified, the cert is a root certificate, or other related situations.
	ResultNonRevokable
	// ResultUnknown is a Result that indicates that some error other than a
	// revocation was encountered during the revocation check
	ResultUnknown
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

// CertRevocationResult encapsulates the result for a single certificate in the
// chain as well as the results from individual servers associated with this
// certificate
type CertRevocationResult struct {
	// Result of revocation for a specific cert in the chain
	//
	// If there are multiple ServerResults with different Results, then this
	// Result will be the most significant of the Results. It will be set
	// according to the following precendence:
	//  ResultOK -> ResultNonRevocable -> ResultUnknown -> ResultRevoked
	// (e.g. If there are 3 ServerResults, 2 of which have a result of
	// ResultUnknown and one that is ResultNonRevocable, this Result value for
	// the certificate would be ResultUnknown)
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
