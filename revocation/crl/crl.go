// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package crl provides methods for checking the revocation status of a
// certificate using CRL
package crl

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
)

var (
	// oidInvalidityDate is the object identifier for the invalidity date
	// CRL entry extension. (See RFC 5280, Section 5.3.2)
	oidInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
)

// Options specifies values that are needed to check CRL
type Options struct {
	// HTTPClient is the HTTP client used to download CRL
	HTTPClient *http.Client

	// SigningTime is the time when the certificate's private key is used to
	// sign the data.
	SigningTime time.Time
}

// CertCheckStatus checks the revocation status of a certificate using CRL
//
// The function checks the revocation status of the certificate by downloading
// the CRL from the CRL distribution points specified in the certificate.
//
// If the invalidity date extension is present in the CRL entry and SigningTime
// is not zero, the certificate is considered revoked if the SigningTime is
// after the invalidity date. (See RFC 5280, Section 5.3.2)
func CertCheckStatus(ctx context.Context, cert, issuer *x509.Certificate, opts Options) *result.CertRevocationResult {
	if opts.HTTPClient == nil {
		return &result.CertRevocationResult{Error: errors.New("invalid input: a non-nil httpClient must be specified")}
	}

	if !SupportCRL(cert) {
		return &result.CertRevocationResult{Error: errors.New("certificate does not support CRL")}
	}

	// Check CRLs
	crlResults := make([]*result.CRLResult, len(cert.CRLDistributionPoints))
	for i, crlURL := range cert.CRLDistributionPoints {
		baseCRL, err := download(ctx, crlURL, opts.HTTPClient)
		if err != nil {
			crlResults[i] = &result.CRLResult{
				Error: fmt.Errorf("failed to download CRL from %s: %w", crlURL, err),
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

		return checkRevocation(cert, baseCRL, opts.SigningTime)
	}

	return &result.CertRevocationResult{
		Result:     result.ResultUnknown,
		CRLResults: crlResults,
		Error:      crlResults[len(crlResults)-1].Error}
}

// SupportCRL checks if the certificate supports CRL.
func SupportCRL(cert *x509.Certificate) bool {
	return len(cert.CRLDistributionPoints) > 0
}

func validate(crl *x509.RevocationList, issuer *x509.Certificate) error {
	// check signature
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL signature verification failed: %w", err)
	}

	// check validity
	if !crl.NextUpdate.IsZero() && time.Now().After(crl.NextUpdate) {
		return fmt.Errorf("CRL is expired: %v", crl.NextUpdate)
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
func checkRevocation(cert *x509.Certificate, baseCRL *x509.RevocationList, signingTime time.Time) *result.CertRevocationResult {
	if cert == nil {
		return &result.CertRevocationResult{Error: errors.New("certificate is nil")}
	}

	if baseCRL == nil {
		return &result.CertRevocationResult{Error: errors.New("CRL is nil")}
	}

	// tempRevokedEntries contains revocation entries with reasons such as
	// CertificateHold or RemoveFromCRL.
	//
	// If the certificate is revoked with CertificateHold, it is temporarily
	// revoked. If the certificate is shown in the CRL with RemoveFromCRL,
	// it is unrevoked.
	var tempRevokedEntries []x509.RevocationListEntry

	for _, revocationEntry := range baseCRL.RevokedCertificateEntries {
		if revocationEntry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			extensions, err := parseEntryExtensions(revocationEntry)
			if err != nil {
				return &result.CertRevocationResult{
					Result: result.ResultUnknown,
					CRLResults: []*result.CRLResult{
						{
							Error: err,
						},
					},
					Error: err,
				}
			}

			// validate signingTime and invalidityDate
			if !signingTime.IsZero() && !extensions.invalidityDate.IsZero() &&
				signingTime.Before(extensions.invalidityDate) {
				// signing time is before the invalidity date which means the
				// certificate is not revoked at the time of signing.
				continue
			}

			if result.CRLReasonCodeCertificateHold.Equal(revocationEntry.ReasonCode) ||
				result.CRLReasonCodeRemoveFromCRL.Equal(revocationEntry.ReasonCode) {
				// temporarily revoked
				tempRevokedEntries = append(tempRevokedEntries, revocationEntry)
			} else {
				// permanently revoked
				return &result.CertRevocationResult{
					Result: result.ResultRevoked,
					CRLResults: []*result.CRLResult{{
						ReasonCode:     result.CRLReasonCode(revocationEntry.ReasonCode),
						RevocationTime: revocationEntry.RevocationTime}},
				}
			}
		}
	}

	// check if the revocation with CertificateHold or RemoveFromCRL
	if len(tempRevokedEntries) > 0 {
		// sort by revocation time (ascending order)
		sort.Slice(tempRevokedEntries, func(i, j int) bool {
			return tempRevokedEntries[i].RevocationTime.Before(tempRevokedEntries[j].RevocationTime)
		})

		// the revocation status depends on the most recent one
		lastEntry := tempRevokedEntries[len(tempRevokedEntries)-1]
		if !result.CRLReasonCodeRemoveFromCRL.Equal(lastEntry.ReasonCode) {
			return &result.CertRevocationResult{
				Result: result.ResultRevoked,
				CRLResults: []*result.CRLResult{{
					ReasonCode:     result.CRLReasonCode(lastEntry.ReasonCode),
					RevocationTime: lastEntry.RevocationTime}},
			}
		}
	}

	return &result.CertRevocationResult{
		Result:     result.ResultOK,
		CRLResults: []*result.CRLResult{},
	}
}

type entryExtensions struct {
	// invalidityDate is the date when the key is invalid.
	invalidityDate time.Time
}

func parseEntryExtensions(entry x509.RevocationListEntry) (entryExtensions, error) {
	extensions := entryExtensions{}
	for _, ext := range entry.ExtraExtensions {
		switch {
		case ext.Id.Equal(oidInvalidityDate):
			var invalidityDate time.Time
			rest, err := asn1.UnmarshalWithParams(ext.Value, &invalidityDate, "generalized")
			if err != nil {
				return entryExtensions{}, fmt.Errorf("failed to parse invalidity date: %w", err)
			}
			if len(rest) > 0 {
				return entryExtensions{}, fmt.Errorf("invalid invalidity date extension")
			}

			extensions.invalidityDate = invalidityDate
		default:
			if ext.Critical {
				// unsupported critical extensions is not allowed. (See RFC 5280, Section 5.2)
				return entryExtensions{}, fmt.Errorf("CRL entry contains unsupported critical extension: %v", ext.Id)
			}
		}
	}

	return extensions, nil
}

func download(ctx context.Context, crlURL string, client *http.Client) (*x509.RevocationList, error) {
	// validate URL
	parsedURL, err := url.Parse(crlURL)
	if err != nil {
		return nil, fmt.Errorf("invalid CRL URL: %w", err)
	}
	if strings.ToLower(parsedURL.Scheme) != "http" {
		return nil, fmt.Errorf("unsupported scheme: %s. Only supports CRL URL in HTTP protocol", parsedURL.Scheme)
	}

	// download CRL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to download with status code: %d", resp.StatusCode)
	}

	// parse CRL
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(data)
}
