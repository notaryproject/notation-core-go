package crl

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
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

// CheckStatus checks the revocation status of the certificate chain.
//
// It caches the CRL and check the revocation status of the certificate chain.
func CheckStatus(opts Options) ([]*result.CertRevocationResult, error) {
	if opts.Cache == nil {
		return nil, errors.New("cache is required")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}

	certResult := make([]*result.CertRevocationResult, len(opts.CertChain))

	var wg sync.WaitGroup
	for i, cert := range opts.CertChain[:len(opts.CertChain)-1] {
		wg.Add(1)
		go func(i int, cert *x509.Certificate) {
			defer wg.Done()
			certResult[i] = CertCheckStatus(cert, opts.CertChain[i+1], opts)
		}(i, cert)
	}

	// Last is root cert, which will never be revoked by OCSP
	certResult[len(opts.CertChain)-1] = &result.CertRevocationResult{
		Result: result.ResultNonRevokable,
		ServerResults: []*result.ServerResult{{
			Result: result.ResultNonRevokable,
			Error:  nil,
		}},
	}

	wg.Wait()
	return certResult, nil
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

	crlFetcher := NewCachedFetcher(opts.HTTPClient, opts.Cache)

	// Check CRL
	var lastError error
	for _, crlURL := range cert.CRLDistributionPoints {
		crlStore, err := crlFetcher.Fetch(crlURL)
		if err != nil {
			lastError = err
			continue
		}

		// validate CRL
		baseCRLStore, ok := crlStore.(BaseCRLStore)
		if !ok {
			lastError = errors.New("invalid CRL store")
			continue
		}
		err = validateCRL(baseCRLStore.BaseCRL(), issuer)
		if err != nil {
			lastError = err
			continue
		}

		if err := crlStore.Save(); err != nil {
			lastError = err
			continue
		}

		// check revocation
		var (
			revoked             bool
			lastRevocationEntry x509.RevocationListEntry
		)
		for _, revocationEntry := range baseCRLStore.BaseCRL().RevokedCertificateEntries {
			if revocationEntry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				lastRevocationEntry = revocationEntry
				if revocationEntry.ReasonCode == int(result.CRLReasonCodeCertificateHold) {
					revoked = true
				} else if revocationEntry.ReasonCode == int(result.CRLReasonCodeRemoveFromCRL) {
					revoked = false
				} else {
					revoked = true
					break
				}
			}
		}
		if revoked {
			return &result.CertRevocationResult{
				Result:    result.ResultRevoked,
				CRLStatus: result.NewCRLStatus(lastRevocationEntry),
			}
		}

		return &result.CertRevocationResult{
			Result: result.ResultOK,
		}
	}

	return &result.CertRevocationResult{Result: result.ResultUnknown, Error: lastError}
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
