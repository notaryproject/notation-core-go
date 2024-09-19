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

// Package crl provides Fetcher and Cache interface and implementations for
// fetching CRLs.
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
	"time"
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
	Fetch(ctx context.Context, url string) (bundle *Bundle, err error)
}

// HTTPFetcher is a Fetcher implementation that fetches CRL from the given URL
type HTTPFetcher struct {
	// Cache stores fetched CRLs and reuses them until the CRL reaches the
	// NextUpdate time.
	// If Cache is nil, no cache is used.
	Cache Cache

	httpClient *http.Client
}

// NewHTTPFetcher creates a new HTTPFetcher with the given HTTP client
func NewHTTPFetcher(httpClient *http.Client) (*HTTPFetcher, error) {
	if httpClient == nil {
		return nil, errors.New("httpClient is nil")
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
func (f *HTTPFetcher) Fetch(ctx context.Context, url string) (bundle *Bundle, err error) {
	if url == "" {
		return nil, errors.New("CRL URL is empty")
	}

	if f.Cache == nil {
		// no cache, download directly
		return f.download(ctx, url)
	}

	// try to get from cache
	bundle, cacheError := f.Cache.Get(ctx, url)
	if cacheError != nil {
		bundle, err := f.download(ctx, url)
		if err != nil {
			var cacheError *CacheError
			if errors.As(err, &cacheError) {
				return bundle, cacheError
			}
			return nil, err
		}
		return bundle, &CacheError{
			Err: fmt.Errorf("failed to get CRL from cache: %w", cacheError),
		}
	}

	// check expiry
	nextUpdate := bundle.BaseCRL.NextUpdate
	if !nextUpdate.IsZero() && time.Now().After(nextUpdate) {
		return f.download(ctx, url)
	}

	return bundle, nil
}

// download downloads the CRL from the given URL and saves it to the
// cache
func (f *HTTPFetcher) download(ctx context.Context, url string) (bundle *Bundle, err error) {
	base, err := download(ctx, url, f.httpClient)
	if err != nil {
		return nil, err
	}
	// check deltaCRL
	for _, ext := range base.Extensions {
		if ext.Id.Equal(oidFreshestCRL) {
			// TODO: support delta CRL
			return nil, errors.New("delta CRL is not supported")
		}
	}

	bundle = &Bundle{
		BaseCRL: base,
	}

	if f.Cache == nil {
		// no cache, return directly
		return bundle, nil
	}

	cacheError := f.Cache.Set(ctx, url, bundle)
	if cacheError != nil {
		return bundle, &CacheError{
			Err: fmt.Errorf("failed to set CRL to cache: %w", cacheError),
		}
	}

	return bundle, nil
}

func download(ctx context.Context, baseURL string, client *http.Client) (*x509.RevocationList, error) {
	// validate URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid CRL URL: %w", err)
	}
	if parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("unsupported scheme: %s. Only supports CRL URL in HTTP protocol", parsedURL.Scheme)
	}

	// download CRL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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