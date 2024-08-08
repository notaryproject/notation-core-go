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
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
)

// oidInvalidityDate is the object identifier for the invalidity date
// CRL entry extension. (See RFC 5280, Section 5.3.2)
var oidInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}

// maxCRLSize is the maximum size of CRL in bytes
const maxCRLSize = 64 * 1024 * 1024 // 64 MiB

// Options specifies values that are needed to check CRL
type Options struct {
	// HTTPClient is the HTTP client used to download CRL
	HTTPClient *http.Client

	// SigningTime is used to compare with the invalidity date during revocation
	// check
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
	if !Supported(cert) {
		return &result.CertRevocationResult{
			Result: result.ResultNonRevokable,
			CRLResults: []*result.CRLResult{{
				Error: fmt.Errorf("CRL is not supported in the certificate %s", cert.Subject.CommonName),
			}},
		}
	}

	if opts.HTTPClient == nil {
		return &result.CertRevocationResult{
			Result: result.ResultUnknown,
			CRLResults: []*result.CRLResult{{
				Error: errors.New("HTTP client is nil"),
			}},
		}
	}

	// The CRLDistributionPoints contains the URIs of all the CRL distribution
	// points. Since it does not distinguish the reason field, it needs to check
	// all the URIs to avoid missing any partial CRLs.
	//
	// For the majority of the certificates, there is only one CRL distribution
	// point with one CRL URI, which will be cached, so checking all the URIs is
	// not a performance issue.
	var (
		crlResults []*result.CRLResult
		lastErr    error
		crlURL     string
	)
	for _, crlURL = range cert.CRLDistributionPoints {
		baseCRL, err := download(ctx, crlURL, opts.HTTPClient)
		if err != nil {
			lastErr = fmt.Errorf("failed to download CRL from %s: %w", crlURL, err)
			break
		}

		if err = validate(baseCRL, issuer); err != nil {
			lastErr = fmt.Errorf("failed to validate CRL from %s: %w", crlURL, err)
			break
		}

		crlResult, err := checkRevocation(cert, baseCRL, opts.SigningTime, crlURL)
		if err != nil {
			lastErr = fmt.Errorf("failed to check revocation status from %s: %w", crlURL, err)
			break
		}
		crlResults = append(crlResults, crlResult)

		if crlResult.Result == result.ResultRevoked {
			return &result.CertRevocationResult{
				Result:     result.ResultRevoked,
				CRLResults: crlResults,
			}
		}
	}

	if lastErr != nil {
		crlResults = append(crlResults, &result.CRLResult{
			Result: result.ResultUnknown,
			URI:    crlURL,
			Error:  lastErr,
		})
		return &result.CertRevocationResult{
			Result:     result.ResultUnknown,
			CRLResults: crlResults,
		}
	}

	return &result.CertRevocationResult{
		Result:     result.ResultOK,
		CRLResults: crlResults,
	}
}

// Supported checks if the certificate supports CRL.
func Supported(cert *x509.Certificate) bool {
	return cert != nil && len(cert.CRLDistributionPoints) > 0
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
func checkRevocation(cert *x509.Certificate, baseCRL *x509.RevocationList, signingTime time.Time, crlURL string) (*result.CRLResult, error) {
	if cert == nil {
		return nil, errors.New("certificate is nil")
	}

	if baseCRL == nil {
		return nil, errors.New("CRL is nil")
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
				return nil, err
			}

			// validate signingTime and invalidityDate
			if !signingTime.IsZero() && !extensions.invalidityDate.IsZero() &&
				signingTime.Before(extensions.invalidityDate) {
				// signing time is before the invalidity date which means the
				// certificate is not revoked at the time of signing.
				continue
			}

			if int(result.CRLReasonCodeCertificateHold) == revocationEntry.ReasonCode ||
				int(result.CRLReasonCodeRemoveFromCRL) == revocationEntry.ReasonCode {
				// temporarily revoked or unrevoked
				tempRevokedEntries = append(tempRevokedEntries, revocationEntry)
			} else {
				// permanently revoked
				return &result.CRLResult{
					Result:         result.ResultRevoked,
					ReasonCode:     result.CRLReasonCode(revocationEntry.ReasonCode),
					RevocationTime: revocationEntry.RevocationTime,
					URI:            crlURL,
				}, nil
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
		if int(result.CRLReasonCodeRemoveFromCRL) != lastEntry.ReasonCode {
			return &result.CRLResult{
				Result:         result.ResultRevoked,
				ReasonCode:     result.CRLReasonCode(lastEntry.ReasonCode),
				RevocationTime: lastEntry.RevocationTime,
				URI:            crlURL,
			}, nil
		}
	}

	return &result.CRLResult{
		Result: result.ResultOK,
		URI:    crlURL,
	}, nil
}

type entryExtensions struct {
	// invalidityDate is the date when the key is invalid.
	invalidityDate time.Time
}

func parseEntryExtensions(entry x509.RevocationListEntry) (entryExtensions, error) {
	var extensions entryExtensions
	for _, ext := range entry.Extensions {
		switch {
		case ext.Id.Equal(oidInvalidityDate):
			var invalidityDate time.Time
			rest, err := asn1.UnmarshalWithParams(ext.Value, &invalidityDate, "generalized")
			if err != nil {
				return entryExtensions{}, fmt.Errorf("failed to parse invalidity date: %w", err)
			}
			if len(rest) > 0 {
				return entryExtensions{}, fmt.Errorf("invalid invalidity date extension: trailing data")
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
	if parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("unsupported scheme: %s. Only supports CRL URL in HTTP protocol", parsedURL.Scheme)
	}

	// download CRL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %q: failed to download with status code: %d", resp.Request.Method, resp.Request.URL, resp.StatusCode)
	}

	// read with size limit
	limitedReader := io.LimitReader(resp.Body, maxCRLSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}
	if len(data) == maxCRLSize {
		return nil, fmt.Errorf("%s %q: CRL size reached the %d MiB size limit", resp.Request.Method, resp.Request.URL, maxCRLSize/1024/1024)
	}

	return x509.ParseRevocationList(data)
}