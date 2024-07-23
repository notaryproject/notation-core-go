package crl

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
)

// Options specifies values that are needed to check CRL
type Options struct {
	HTTPClient  *http.Client
	SigningTime time.Time
}

// CertCheckStatus checks the revocation status of a certificate using CRL
func CertCheckStatus(ctx context.Context, cert, issuer *x509.Certificate, opts Options) *result.CertRevocationResult {
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}

	if !HasCRL(cert) {
		return &result.CertRevocationResult{Error: errors.New("certificate does not support CRL")}
	}

	// Check CRLs
	crlResults := make([]*result.CRLResult, len(cert.CRLDistributionPoints))
	for i, crlURL := range cert.CRLDistributionPoints {
		baseCRL, err := download(ctx, crlURL, opts.HTTPClient)
		if err != nil {
			crlResults[i] = &result.CRLResult{
				URL:   crlURL,
				Error: err,
			}
			continue
		}

		err = validate(baseCRL, issuer)
		if err != nil {
			return &result.CertRevocationResult{
				Result:     result.ResultUnknown,
				CRLResults: crlResults,
				Error:      err,
			}
		}

		return checkRevocation(cert, baseCRL, crlURL, opts.SigningTime)
	}

	return &result.CertRevocationResult{
		Result:     result.ResultUnknown,
		CRLResults: crlResults,
		Error:      crlResults[len(crlResults)-1].Error}
}

func validate(crl *x509.RevocationList, issuer *x509.Certificate) error {
	// after NextUpdate time, new CRL will be issued. (See RFC 5280, Section 5.1.2.5)
	if !crl.NextUpdate.IsZero() && time.Now().After(crl.NextUpdate) {
		return fmt.Errorf("CRL is expired: %v", crl.NextUpdate)
	}

	// check signature
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL signature verification failed: %w", err)
	}

	// unsupported critical extensions is not allowed. (See RFC 5280, Section 5.2)
	for _, ext := range crl.Extensions {
		if ext.Critical {
			return fmt.Errorf("CRL contains unsupported critical extension: %v", ext.Id)
		}
	}

	return nil
}

// checkRevocation checks if the certificate is revoked or not
func checkRevocation(cert *x509.Certificate, baseCRL *x509.RevocationList, crlURL string, signingTime time.Time) *result.CertRevocationResult {
	// check revocation
	var (
		revoked             bool
		lastRevocationEntry x509.RevocationListEntry
	)
	for _, revocationEntry := range baseCRL.RevokedCertificateEntries {
		if revocationEntry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			if err := validateRevocationEntry(revocationEntry); err != nil {
				return &result.CertRevocationResult{
					Result: result.ResultUnknown,
					CRLResults: []*result.CRLResult{
						{
							URL:   crlURL,
							Error: err,
						},
					},
					Error: err,
				}
			}

			// validate revocation time
			if !signingTime.IsZero() && signingTime.Before(revocationEntry.RevocationTime) {
				// certificate is revoked after signing time, so it is valid
				continue
			}
			lastRevocationEntry = revocationEntry

			if revocationEntry.ReasonCode == int(result.CRLReasonCodeCertificateHold) {
				// certificate is revoked but not permanently
				revoked = true
			} else if revocationEntry.ReasonCode == int(result.CRLReasonCodeRemoveFromCRL) {
				// certificate has been removed from the CRL
				revoked = false
			} else {
				// permanently revoked
				revoked = true
				break
			}
		}
	}
	if revoked {
		return &result.CertRevocationResult{
			Result: result.ResultRevoked,
			CRLResults: []*result.CRLResult{{
				URL:            crlURL,
				ReasonCode:     result.CRLReasonCode(lastRevocationEntry.ReasonCode),
				RevocationTime: lastRevocationEntry.RevocationTime}},
		}
	}

	return &result.CertRevocationResult{
		Result:     result.ResultOK,
		CRLResults: []*result.CRLResult{{URL: crlURL}},
	}
}

func validateRevocationEntry(entry x509.RevocationListEntry) error {
	// unsupported critical extensions is not allowed. (See RFC 5280, Section 5.2)
	for _, ext := range entry.ExtraExtensions {
		if ext.Critical {
			return fmt.Errorf("CRL entry contains unsupported critical extension: %v", ext.Id)
		}
	}

	return nil
}

// HasCRL checks if the certificate supports CRL.
func HasCRL(cert *x509.Certificate) bool {
	return len(cert.CRLDistributionPoints) > 0
}

func download(ctx context.Context, crlURL string, client *http.Client) (*x509.RevocationList, error) {
	// validate URL
	parsedURL, err := url.Parse(crlURL)
	if err != nil {
		return nil, err
	}

	if parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("unsupported scheme: %s. Only supports CRL URL in HTTP protocol", parsedURL.Scheme)
	}

	// fetch from remote
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to download CRL from %s: %s", crlURL, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseRevocationList(data)
}
