package revocation

import "fmt"

// RevokedInOCSPError is returned when the certificate's status for OCSP is ocsp.Revoked
type RevokedInOCSPError struct{}

func (e RevokedInOCSPError) Error() string {
	return "certificate is revoked via OCSP"
}

// UnknownInOCSPError is returned when the certificate's status for OCSP is ocsp.Unknown
type UnknownInOCSPError struct{}

func (e UnknownInOCSPError) Error() string {
	return "certificate has unknown status via OCSP"
}

// CheckOCSPError is returned when there is an error during the OCSP revocation check, not necessarily a revocation
type CheckOCSPError struct {
	Err error
}

func (e CheckOCSPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("error checking revocation via OCSP: %s", e.Err.Error())
	} else {
		return "error checking revocation via OCSP"
	}
}

// NoOCSPServerError is returned when the OCSPServer is not specified or is not an HTTP URL.
type NoOCSPServerError struct{}

func (e NoOCSPServerError) Error() string {
	return "no valid OCSPServer found"
}

// OCSPTimeoutError is returned when the connection attempt to an OCSP URL exceeds the specified threshold
type OCSPTimeoutError struct{}

func (e OCSPTimeoutError) Error() string {
	return "exceeded timeout threshold for OCSP check"
}
