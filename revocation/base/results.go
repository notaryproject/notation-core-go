// Package base provides general objects that are used across revocation
package base

import "strconv"

// Result is a type of enumerated value to help characterize errors. It can be
// OK, Unknown, or Revoked
type Result int

const (
	// OK is a Result that indicates that the revocation check resulted in no
	// important errors
	OK Result = iota
	// NonRevokable is a Result that indicates that the certificate cannot be
	// checked for revocation. This may be a result of no OCSP servers being
	// specified, the cert is a root certificate, or other related situations.
	NonRevokable
	// Unknown is a Result that indicates that some error other than a
	// revocation was encountered during the revocation check
	Unknown
	// Revoked is a Result that indicates that at least one certificate was
	// revoked when performing a revocation check on the certificate chain
	Revoked
)

// String provides a conversion from a Result to a string
func (r Result) String() string {
	switch r {
	case OK:
		return "OK"
	case NonRevokable:
		return "NonRevokable"
	case Unknown:
		return "Unknown"
	case Revoked:
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

	// Error is set if there is an error associated with the revocation check
	// to this server
	Error error
}

// CertRevocationResult encapsulates the result for a single certificate in the
// chain as well as the results from individual servers associated with this
// certificate
type CertRevocationResult struct {
	// Result of revocation for a specific cert in the chain
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
