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

// Package crl provides Fetcher interface and its implementation to fetch
// CRL from the given URL
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

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
)

// MaxCRLSize is the maximum size of CRL in bytes
//
// CRL examples: https://chasersystems.com/blog/an-analysis-of-certificate-revocation-list-sizes/
const MaxCRLSize = 32 * 1024 * 1024 // 32 MiB

// Fetcher is an interface that specifies methods used for fetching CRL
// from the given URL
type Fetcher interface {
	// Fetch retrieves the CRL from the given URL.
	Fetch(ctx context.Context, uri string) (base, delta *x509.RevocationList, err error)
}

type HTTPFetcher struct {
	// Cache stores fetched CRLs and reuses them with the max ages.
	// If Cache is nil, no cache is used.
	Cache cache.Cache

	httpClient *http.Client
}

func NewHTTPFetcher(httpClient *http.Client) *HTTPFetcher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &HTTPFetcher{
		httpClient: httpClient,
	}
}

// Fetch retrieves the CRL from the given URL
//
// Steps:
//  1. Try to get from cache
//  2. If not exist or broken, download and save to cache
func (f *HTTPFetcher) Fetch(ctx context.Context, uri string) (base, delta *x509.RevocationList, err error) {
	if uri == "" {
		return nil, nil, errors.New("CRL URL is empty")
	}

	if f.Cache == nil {
		// no cache, download directly
		return f.download(ctx, uri)
	}

	// try to get from cache
	bundle, err := f.Cache.Get(ctx, uri)
	if err != nil {
		return f.download(ctx, uri)
	}

	// check expiry
	nextUpdate := bundle.Metadata.BaseCRL.NextUpdate
	if !nextUpdate.IsZero() && time.Now().After(nextUpdate) {
		return f.download(ctx, uri)
	}

	return bundle.BaseCRL, nil, nil
}

// Download downloads the CRL from the given URL and saves it to the
// cache
func (f *HTTPFetcher) download(ctx context.Context, uri string) (base, delta *x509.RevocationList, err error) {
	base, err = download(ctx, uri, f.httpClient)
	if err != nil {
		return nil, nil, err
	}

	if f.Cache == nil {
		// no cache, return directly
		return base, delta, nil
	}

	bundle := &cache.Bundle{
		BaseCRL: base,
		Metadata: cache.Metadata{
			BaseCRL: cache.CRLMetadata{
				URL:        uri,
				NextUpdate: base.NextUpdate,
			},
			CachedAt: time.Now(),
		},
	}
	// ignore the error, as the cache is not critical
	_ = f.Cache.Set(ctx, uri, bundle)

	return base, delta, nil
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to download with status code: %d", resp.StatusCode)
	}
	// read with size limit
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxCRLSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}
	if len(data) == MaxCRLSize {
		return nil, fmt.Errorf("CRL size exceeds the limit: %d", MaxCRLSize)
	}

	// parse CRL
	return x509.ParseRevocationList(data)
}
