package ocsp

import "github.com/notaryproject/notation-core-go/revocation/internal/ocsp"

type (
	// RevokedError is returned when the certificate's status for OCSP is
	// ocsp.Revoked
	RevokedError = ocsp.RevokedError

	// UnknownStatusError is returned when the certificate's status for OCSP is
	// ocsp.Unknown
	UnknownStatusError = ocsp.UnknownStatusError

	// GenericError is returned when there is an error during the OCSP revocation
	// check, not necessarily a revocation
	GenericError = ocsp.GenericError

	// NoServerError is returned when the OCSPServer is not specified.
	NoServerError = ocsp.NoServerError

	// TimeoutError is returned when the connection attempt to an OCSP URL exceeds
	// the specified threshold
	TimeoutError = ocsp.TimeoutError
)
