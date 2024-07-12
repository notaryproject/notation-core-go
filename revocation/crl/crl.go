package crl

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
	"github.com/notaryproject/notation-core-go/revocation/result"
)

// Options specifies values that are needed to check OCSP revocation
type Options struct {
	CertChain  []*x509.Certificate
	HTTPClient *http.Client
	Cache      cache.Cache
}

func CertCheckStatus(cert, issuer *x509.Certificate, opts Options) *result.CertRevocationResult {
	if opts.Cache == nil {
		return &result.CertRevocationResult{Error: errors.New("cache is required")}
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	if !HasCRL(cert) {
		return &result.CertRevocationResult{Error: errors.New("certificate does not support CRL")}
	}

	crlFetcher := NewCachedCRLFetcher(opts.HTTPClient, opts.Cache)

	// Check CRL
	var lastError error
	for _, crlURL := range cert.CRLDistributionPoints {
		crlStore, cached, err := crlFetcher.Fetch(crlURL)
		if err != nil {
			lastError = err
			continue
		}

		err = validateCRL(crlStore.BaseCRL(), issuer)
		if err != nil {
			lastError = err
			continue
		}

		if !cached {
			if err := crlStore.Save(); err != nil {
				lastError = err
				continue
			}
		}

		// check revocation
		for _, revokedCert := range crlStore.BaseCRL().RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return &result.CertRevocationResult{
					Result:    result.ResultRevoked,
					CRLStatus: result.NewCRLStatus(revokedCert),
				}
			}
		}

		return &result.CertRevocationResult{
			Result: result.ResultOK,
		}
	}

	return &result.CertRevocationResult{Result: result.ResultNonRevokable, Error: lastError}
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

	// check extensions
	for _, ext := range crl.Extensions {
		if ext.Critical {
			return fmt.Errorf("CRL contains unsupported critical extension: %v", ext.Id)
		}
	}

	return nil
}

// HasCRL checks if the certificate supports CRL.
func HasCRL(cert *x509.Certificate) bool {
	return len(cert.CRLDistributionPoints) > 0
}
