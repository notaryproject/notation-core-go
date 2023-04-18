// Package ocsp provides methods for checking the OCSP revocation status of a
// certificate chain, as well as errors related to these checks
package ocsp

import (
	"fmt"
	"time"
)

// RevokedError is returned when the certificate's status for OCSP is
// ocsp.Revoked
type RevokedError struct{}

func (e RevokedError) Error() string {
	return "certificate is revoked via OCSP"
}

// UnknownStatusError is returned when the certificate's status for OCSP is
// ocsp.Unknown
type UnknownStatusError struct{}

func (e UnknownStatusError) Error() string {
	return "certificate has unknown status via OCSP"
}

// GenericError is returned when there is an error during the OCSP revocation
// check, not necessarily a revocation
type GenericError struct {
	Err error
}

func (e GenericError) Error() string {
	msg := "error checking revocation status via OCSP"
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

// NoServerError is returned when the OCSPServer is not specified.
type NoServerError struct{}

func (e NoServerError) Error() string {
	return "no valid OCSP server found"
}

// TimeoutError is returned when the connection attempt to an OCSP URL exceeds
// the specified threshold
type TimeoutError struct {
	timeout time.Duration
}

func (e TimeoutError) Error() string {
	return fmt.Sprintf("exceeded timeout threshold of %.2f seconds for OCSP check", e.timeout.Seconds())
}
