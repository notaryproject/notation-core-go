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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-core-go/revocation/result"
)

var (
	// oidFreshestCRL is the object identifier for the distribution point
	// for the delta CRL. (See RFC 5280, Section 5.2.6)
	oidFreshestCRL = asn1.ObjectIdentifier{2, 5, 29, 46}

	// oidIssuingDistributionPoint is the object identifier for the issuing
	// distribution point CRL extension. (See RFC 5280, Section 5.2.5)
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}

	// oidInvalidityDate is the object identifier for the invalidity date
	// CRL entry extension. (See RFC 5280, Section 5.3.2)
	oidInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
)

// CertCheckStatusOptions specifies values that are needed to check CRL.
type CertCheckStatusOptions struct {
	// Fetcher is used to fetch the CRL from the CRL distribution points.
	Fetcher crl.Fetcher

	// SigningTime is used to compare with the invalidity date during revocation
	// check.
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
func CertCheckStatus(ctx context.Context, cert, issuer *x509.Certificate, opts CertCheckStatusOptions) *result.CertRevocationResult {
	if !Supported(cert) {
		// CRL not enabled for this certificate.
		return &result.CertRevocationResult{
			Result: result.ResultNonRevokable,
			ServerResults: []*result.ServerResult{{
				RevocationMethod: result.RevocationMethodCRL,
				Error:            errors.New("CRL is not supported"),
				Result:           result.ResultNonRevokable,
			}},
			RevocationMethod: result.RevocationMethodCRL,
		}
	}

	if opts.Fetcher == nil {
		return &result.CertRevocationResult{
			Result: result.ResultUnknown,
			ServerResults: []*result.ServerResult{{
				RevocationMethod: result.RevocationMethodCRL,
				Error:            errors.New("CRL fetcher cannot be nil"),
				Result:           result.ResultUnknown,
			}},
			RevocationMethod: result.RevocationMethodCRL,
		}
	}

	var (
		serverResults  = make([]*result.ServerResult, 0, len(cert.CRLDistributionPoints))
		lastErr        error
		crlURL         string
		hasFreshestCRL = hasFreshestCRL(&cert.Extensions)
	)

	// The CRLDistributionPoints contains the URIs of all the CRL distribution
	// points. Since it does not distinguish the reason field, it needs to check
	// all the URIs to avoid missing any partial CRLs.
	//
	// For the majority of the certificates, there is only one CRL distribution
	// point with one CRL URI, which will be cached, so checking all the URIs is
	// not a performance issue.
	for _, crlURL = range cert.CRLDistributionPoints {
		var (
			bundle *crl.Bundle
			err    error
		)
		if !hasFreshestCRL {
			bundle, err = opts.Fetcher.Fetch(ctx, crlURL)
			if err != nil {
				lastErr = fmt.Errorf("failed to download CRL from %s: %w", crlURL, err)
				break
			}
		} else {
			fetcher, ok := opts.Fetcher.(crl.FetcherWithCertificateExtensions)
			if !ok {
				lastErr = fmt.Errorf("fetcher does not support fetching delta CRL from certificate extension")
				break
			}
			bundle, err = fetcher.FetchWithCertificateExtensions(ctx, crlURL, &cert.Extensions)
			if err != nil {
				lastErr = fmt.Errorf("failed to download CRL from %s: %w", crlURL, err)
				break
			}
		}

		if err = validate(bundle.BaseCRL, issuer); err != nil {
			lastErr = fmt.Errorf("failed to validate CRL from %s: %w", crlURL, err)
			break
		}
		if bundle.DeltaCRL != nil {
			if err = validate(bundle.DeltaCRL, issuer); err != nil {
				lastErr = fmt.Errorf("failed to validate delta CRL from %s: %w", crlURL, err)
				break
			}
		}

		crlResult, err := checkRevocation(cert, bundle, opts.SigningTime, crlURL)
		if err != nil {
			lastErr = fmt.Errorf("failed to check revocation status from %s: %w", crlURL, err)
			break
		}

		if crlResult.Result == result.ResultRevoked {
			return &result.CertRevocationResult{
				Result:           result.ResultRevoked,
				ServerResults:    []*result.ServerResult{crlResult},
				RevocationMethod: result.RevocationMethodCRL,
			}
		}

		serverResults = append(serverResults, crlResult)
	}

	if lastErr != nil {
		return &result.CertRevocationResult{
			Result: result.ResultUnknown,
			ServerResults: []*result.ServerResult{
				{
					Result:           result.ResultUnknown,
					Server:           crlURL,
					Error:            lastErr,
					RevocationMethod: result.RevocationMethodCRL,
				}},
			RevocationMethod: result.RevocationMethodCRL,
		}
	}

	return &result.CertRevocationResult{
		Result:           result.ResultOK,
		ServerResults:    serverResults,
		RevocationMethod: result.RevocationMethodCRL,
	}
}

// Supported checks if the certificate supports CRL.
func Supported(cert *x509.Certificate) bool {
	return cert != nil && len(cert.CRLDistributionPoints) > 0
}

func hasFreshestCRL(extensions *[]pkix.Extension) bool {
	for _, ext := range *extensions {
		if ext.Id.Equal(oidFreshestCRL) {
			return true
		}
	}
	return false
}

func validate(crl *x509.RevocationList, issuer *x509.Certificate) error {
	// check signature
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL is not signed by CA %s: %w,", issuer.Subject, err)
	}

	// check validity
	if crl.NextUpdate.IsZero() {
		return errors.New("CRL NextUpdate is not set")
	}
	now := time.Now()
	if now.After(crl.NextUpdate) {
		return fmt.Errorf("expired CRL. Current time %v is after CRL NextUpdate %v", now, crl.NextUpdate)
	}

	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidIssuingDistributionPoint):
			// IssuingDistributionPoint is a critical extension that identifies
			// the scope of the CRL. Since we will check all the CRL
			// distribution points, it is not necessary to check this extension.
		default:
			if ext.Critical {
				// unsupported critical extensions is not allowed. (See RFC 5280, Section 5.2)
				return fmt.Errorf("unsupported critical extension found in CRL: %v", ext.Id)
			}
		}
	}

	return nil
}

// checkRevocation checks if the certificate is revoked or not
func checkRevocation(cert *x509.Certificate, bundle *crl.Bundle, signingTime time.Time, crlURL string) (*result.ServerResult, error) {
	if cert == nil {
		return nil, errors.New("certificate cannot be nil")
	}
	if bundle == nil {
		return nil, errors.New("CRL bundle cannot be nil")
	}
	baseCRL := bundle.BaseCRL
	if baseCRL == nil {
		return nil, errors.New("baseCRL cannot be nil")
	}

	deltaCRL := bundle.DeltaCRL
	entriesArray := []*[]x509.RevocationListEntry{&baseCRL.RevokedCertificateEntries}
	if deltaCRL != nil {
		entriesArray = append(entriesArray, &deltaCRL.RevokedCertificateEntries)
	}

	// latestTempRevokedEntry contains the most recent revocation entry with
	// reasons such as CertificateHold or RemoveFromCRL.
	//
	// If the certificate is revoked with CertificateHold, it is temporarily
	// revoked. If the certificate is shown in the CRL with RemoveFromCRL,
	// it is unrevoked.
	var latestTempRevokedEntry *x509.RevocationListEntry

	// iterate over all the entries in the base and delta CRLs
	for _, entries := range entriesArray {
		for i, revocationEntry := range *entries {
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
					break
				}

				switch revocationEntry.ReasonCode {
				case int(reasonCodeCertificateHold), int(reasonCodeRemoveFromCRL):
					// temporarily revoked or unrevoked
					if latestTempRevokedEntry == nil || latestTempRevokedEntry.RevocationTime.Before(revocationEntry.RevocationTime) {
						// the revocation status depends on the most recent reason
						latestTempRevokedEntry = &baseCRL.RevokedCertificateEntries[i]
					}
				default:
					// permanently revoked
					return &result.ServerResult{
						Result:           result.ResultRevoked,
						Server:           crlURL,
						RevocationMethod: result.RevocationMethodCRL,
					}, nil
				}
			}
		}
	}
	if latestTempRevokedEntry != nil && latestTempRevokedEntry.ReasonCode == reasonCodeCertificateHold {
		// revoked with CertificateHold
		return &result.ServerResult{
			Result:           result.ResultRevoked,
			Server:           crlURL,
			RevocationMethod: result.RevocationMethodCRL,
		}, nil
	}

	return &result.ServerResult{
		Result:           result.ResultOK,
		Server:           crlURL,
		RevocationMethod: result.RevocationMethodCRL,
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
				return entryExtensions{}, fmt.Errorf("unsupported critical extension found in CRL: %v", ext.Id)
			}
		}
	}

	return extensions, nil
}
