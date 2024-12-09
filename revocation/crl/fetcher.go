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

// Package crl provides Fetcher interface with its implementation, and the
// Cache interface.
package crl

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// oidFreshestCRL is the object identifier for the distribution point
// for the delta CRL. (See RFC 5280, Section 5.2.6)
var oidFreshestCRL = asn1.ObjectIdentifier{2, 5, 29, 46}

// maxCRLSize is the maximum size of CRL in bytes
//
// The 32 MiB limit is based on investigation that even the largest CRLs
// are less than 16 MiB. The limit is set to 32 MiB to prevent
const maxCRLSize = 32 * 1024 * 1024 // 32 MiB

// Fetcher is an interface that specifies methods used for fetching CRL
// from the given URL
type Fetcher interface {
	// Fetch retrieves the CRL from the given URL.
	Fetch(ctx context.Context, url string) (*Bundle, error)
}

// HTTPFetcher is a Fetcher implementation that fetches CRL from the given URL
type HTTPFetcher struct {
	// Cache stores fetched CRLs and reuses them until the CRL reaches the
	// NextUpdate time.
	// If Cache is nil, no cache is used.
	Cache Cache

	// DiscardCacheError specifies whether to discard any error on cache.
	//
	// ErrCacheMiss is not considered as an failure and will not be returned as
	// an error if DiscardCacheError is false.
	DiscardCacheError bool

	httpClient *http.Client
}

// NewHTTPFetcher creates a new HTTPFetcher with the given HTTP client
func NewHTTPFetcher(httpClient *http.Client) (*HTTPFetcher, error) {
	if httpClient == nil {
		return nil, errors.New("httpClient cannot be nil")
	}

	return &HTTPFetcher{
		httpClient: httpClient,
	}, nil
}

// Fetch retrieves the CRL from the given URL
//
// If cache is not nil, try to get the CRL from the cache first. On failure
// (e.g. cache miss), it will download the CRL from the URL and store it to the
// cache.
func (f *HTTPFetcher) Fetch(ctx context.Context, url string) (*Bundle, error) {
	if url == "" {
		return nil, errors.New("CRL URL cannot be empty")
	}

	if f.Cache != nil {
		bundle, err := f.Cache.Get(ctx, url)
		if err == nil {
			// check expiry of base CRL and delta CRL
			if (bundle.BaseCRL != nil && isEffective(bundle.BaseCRL)) &&
				(bundle.DeltaCRL == nil || isEffective(bundle.DeltaCRL)) {
				return bundle, nil
			}
		} else if !errors.Is(err, ErrCacheMiss) && !f.DiscardCacheError {
			return nil, fmt.Errorf("failed to retrieve CRL from cache: %w", err)
		}
	}

	bundle, err := f.fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve CRL: %w", err)
	}

	if f.Cache != nil {
		err = f.Cache.Set(ctx, url, bundle)
		if err != nil && !f.DiscardCacheError {
			return nil, fmt.Errorf("failed to store CRL to cache: %w", err)
		}
	}

	return bundle, nil
}

// isEffective checks if the CRL is effective by checking the NextUpdate time.
func isEffective(crl *x509.RevocationList) bool {
	return !crl.NextUpdate.IsZero() && !time.Now().After(crl.NextUpdate)
}

// fetch downloads the CRL from the given URL.
func (f *HTTPFetcher) fetch(ctx context.Context, url string) (*Bundle, error) {
	// fetch base CRL
	base, err := fetchCRL(ctx, url, f.httpClient)
	if err != nil {
		return nil, err
	}

	// fetch delta CRL from base CRL extension
	deltaCRL, err := f.fetchDeltaCRL(&base.Extensions)
	if err != nil && !errors.Is(err, errDeltaCRLNotFound) {
		return nil, err
	}

	return &Bundle{
		BaseCRL:  base,
		DeltaCRL: deltaCRL,
	}, nil
}

// fetchDeltaCRL fetches the delta CRL from the given extensions of base CRL.
//
// It returns errDeltaCRLNotFound if the delta CRL is not found.
func (f *HTTPFetcher) fetchDeltaCRL(extensions *[]pkix.Extension) (*x509.RevocationList, error) {
	var (
		lastError error
		deltaCRL  *x509.RevocationList
	)
	for _, ext := range *extensions {
		if ext.Id.Equal(oidFreshestCRL) {
			// RFC 5280, 4.2.1.15
			//    id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }
			//
			//    FreshestCRL ::= CRLDistributionPoints
			urls, err := parseCRLDistributionPoint(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to parse Freshest CRL extension: %w", err)
			}

			for _, cdpURL := range urls {
				// RFC 5280, 5.2.6
				// Delta CRLs from the base CRL have the same scope as the base
				// CRL, so the URLs are for redundancy and should be tried in
				// order until one succeeds.
				deltaCRL, lastError = fetchCRL(context.Background(), cdpURL, f.httpClient)
				if lastError == nil {
					return deltaCRL, nil
				}
			}
			break
		}
	}
	if lastError != nil {
		return nil, lastError
	}
	return nil, errDeltaCRLNotFound
}

// parseCRLDistributionPoint parses the CRL extension and returns the CRL URLs
//
// value is the raw value of the CRL distribution point extension
func parseCRLDistributionPoint(value []byte) ([]string, error) {
	var urls []string
	// borrowed from crypto/x509: https://cs.opensource.google/go/go/+/refs/tags/go1.23.4:src/crypto/x509/parser.go;l=700-743
	//
	// RFC 5280, 4.2.1.13
	//
	// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
	//
	// DistributionPoint ::= SEQUENCE {
	//     distributionPoint       [0]     DistributionPointName OPTIONAL,
	//     reasons                 [1]     ReasonFlags OPTIONAL,
	//     cRLIssuer               [2]     GeneralNames OPTIONAL }
	//
	// DistributionPointName ::= CHOICE {
	//     fullName                [0]     GeneralNames,
	//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
	val := cryptobyte.String(value)
	if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid CRL distribution points")
	}
	for !val.Empty() {
		var dpDER cryptobyte.String
		if !val.ReadASN1(&dpDER, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("x509: invalid CRL distribution point")
		}
		var dpNameDER cryptobyte.String
		var dpNamePresent bool
		if !dpDER.ReadOptionalASN1(&dpNameDER, &dpNamePresent, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("x509: invalid CRL distribution point")
		}
		if !dpNamePresent {
			continue
		}
		if !dpNameDER.ReadASN1(&dpNameDER, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("x509: invalid CRL distribution point")
		}
		for !dpNameDER.Empty() {
			if !dpNameDER.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
				break
			}
			var uri cryptobyte.String
			if !dpNameDER.ReadASN1(&uri, cryptobyte_asn1.Tag(6).ContextSpecific()) {
				return nil, errors.New("x509: invalid CRL distribution point")
			}
			urls = append(urls, string(uri))
		}
	}
	return urls, nil
}

func fetchCRL(ctx context.Context, crlURL string, client *http.Client) (*x509.RevocationList, error) {
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download with status code: %d", resp.StatusCode)
	}
	// read with size limit
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}
	if len(data) == maxCRLSize {
		return nil, fmt.Errorf("CRL size exceeds the limit: %d", maxCRLSize)
	}

	// parse CRL
	return x509.ParseRevocationList(data)
}
