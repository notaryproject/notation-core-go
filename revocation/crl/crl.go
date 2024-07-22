package crl

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
)

// Options specifies values that are needed to check OCSP revocation
type Options struct {
	CertChain  []*x509.Certificate
	HTTPClient *http.Client
}

func CertCheckStatus(cert, issuer *x509.Certificate, opts Options) *result.CertRevocationResult {
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	if !HasCRL(cert) {
		return &result.CertRevocationResult{Error: errors.New("certificate does not support CRL")}
	}

	// Check CRL
	var lastError error
	for _, crlURL := range cert.CRLDistributionPoints {
		baseCRL, err := download(crlURL, opts.HTTPClient)
		if err != nil {
			lastError = err
			continue
		}

		err = validateCRL(baseCRL, issuer)
		if err != nil {
			lastError = err
			continue
		}

		// check revocation
		var (
			revoked             bool
			lastRevocationEntry x509.RevocationListEntry
		)
		for _, revocationEntry := range baseCRL.RevokedCertificateEntries {
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

func download(url string, httpClient *http.Client) (*x509.RevocationList, error) {
	// fetch from remote
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseRevocationList(data)
}
