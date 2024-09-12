package revocation

import (
	"github.com/notaryproject/notation-core-go/revocation/internal/crl"
	"github.com/notaryproject/notation-core-go/revocation/internal/ocsp"
)

const (
	// MethodUnknown is used for root certificates or when the method
	// used to check the revocation status of a certificate is unknown.
	MethodUnknown int = 0

	// MethodOCSP represents OCSP as the method used to check the
	// revocation status of a certificate
	MethodOCSP = ocsp.RevocationMethodOCSP

	// MethodCRL represents CRL as the method used to check the
	// revocation status of a certificate
	MethodCRL = crl.RevocationMethodCRL

	// MethodOCSPFallbackCRL represents OCSP check with unknown error
	// fallback to CRL as the method used to check the revocation status of a
	// certificate
	MethodOCSPFallbackCRL = 3
)
