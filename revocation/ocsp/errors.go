// Package OCSP provides methods for checking the OCSP revocation status of a
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

// OCSPCheckError is returned when there is an error during the OCSP revocation
// check, not necessarily a revocation
type OCSPCheckError struct {
	Err error
}

func (e OCSPCheckError) Error() string {
	msg := "error checking revocation status via OCSP"
	if e.Err != nil {
		return fmt.Sprintf("%s: %s", msg, e.Err.Error())
	}
	return msg
}

// NoOCSPServerError is returned when the OCSPServer is not specified.
type NoOCSPServerError struct{}

func (e NoOCSPServerError) Error() string {
	return "no valid OCSPServer found"
}

// PKIXNoCheckError is returned when the OCSP signing cert is missing the
// id-pkix-ocsp-nocheck extension.
type PKIXNoCheckError struct{}

func (e PKIXNoCheckError) Error() string {
	return fmt.Sprintf("an OCSP signing cert is missing the id-pkix-ocsp-nocheck extension (%s)", pkixNoCheckOID)
}

// TimeoutError is returned when the connection attempt to an OCSP URL exceeds
// the specified threshold
type TimeoutError struct {
	timeout time.Duration
}

func (e TimeoutError) Error() string {
	return fmt.Sprintf("exceeded timeout threshold of %.2f seconds for OCSP check", e.timeout.Seconds())
}

// InvalidChainError is returned when the certificate chain does not meet the
// requirements for a valid certificate chain
type InvalidChainError struct {
	Err           error
	IsInvalidRoot bool
}

func (e InvalidChainError) Error() string {
	msg := "invalid chain: expected chain to be correct and complete"
	if e.IsInvalidRoot {
		msg = "invalid chain: expected chain to end with root cert"
	}

	if e.Err != nil {
		return fmt.Sprintf("%s: %s", msg, e.Err.Error())
	}
	return msg
}
