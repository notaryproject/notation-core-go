package crl

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
)

// Options specifies values that are needed to check OCSP revocation
type Options struct {
	CertChain  []*x509.Certificate
	HTTPClient *http.Client
	Cache      Cache
}

func CertCheckStatus(cert, issuer *x509.Certificate, opts Options) *result.CertRevocationResult {
	if opts.Cache == nil {
		return &result.CertRevocationResult{Err: errors.New("cache is required")}
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	if !HasCRL(cert) {
		return &result.CertRevocationResult{Err: errors.New("certificate does not support CRL")}
	}

	crlClient := NewCRLClient(opts.Cache, opts.HTTPClient)

	// Check CRL
	var lastError error
	for _, crlURL := range cert.CRLDistributionPoints {
		crl, err := crlClient.Fetch(crlURL)
		if err != nil {
			lastError = err
			continue
		}

		err = validateCRL(crl, issuer)
		if err != nil {
			lastError = err
			continue
		}

		// check revocation
		for _, revokedCert := range crl.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return &result.CertRevocationResult{
					Result: result.ResultRevoked,
					ServerResults: []*result.ServerResult{{
						Result: result.ResultNonRevokable,
						Error:  nil,
					}},
				}
			}
		}

		return &result.CertRevocationResult{
			Result: result.ResultOK,
			ServerResults: []*result.ServerResult{{
				Result: result.ResultOK,
				Error:  nil,
			}},
		}
	}

	return &result.CertRevocationResult{Err: lastError}
}

func validateCRL(crl *x509.RevocationList, issuer *x509.Certificate) error {
	// check crl expiration
	if time.Now().After(crl.NextUpdate) {
		return errors.New("CRL is expired")
	}

	// check signature
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL signature verification failed: %v", err)
	}

	return nil
}

// HasCRL checks if the certificate supports CRL.
func HasCRL(cert *x509.Certificate) bool {
	return len(cert.CRLDistributionPoints) > 0
}
