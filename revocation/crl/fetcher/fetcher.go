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

// Package fetcher provides Fetcher interface and its implementation to fetch
// CRL from the given URL
package fetcher

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

// maxCRLSize is the maximum size of CRL in bytes
const maxCRLSize = 64 * 1024 * 1024 // 64 MiB

// Fetcher is an interface that specifies methods used for fetching CRL
// from the given URL
type Fetcher interface {
	Fetch(ctx context.Context, crlURL string) (bundle *cache.Bundle, fromCache bool, err error)
}

type cachedFetcher struct {
	httpClient  *http.Client
	cacheClient cache.Cache
}

// NewCachedFetcher creates a new Fetcher with the given HTTP client and cache client
//   - if httpClient is nil, http.DefaultClient will be used
//   - if cacheClient is nil, no cache will be used
func NewCachedFetcher(httpClient *http.Client, cacheClient cache.Cache) (Fetcher, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	if cacheClient == nil {
		return nil, errors.New("cache client is nil")
	}

	return &cachedFetcher{
		httpClient:  httpClient,
		cacheClient: cacheClient,
	}, nil
}

// Fetch retrieves the CRL from the given URL
//
// Steps:
//  1. Try to get from cache
//  2. If not exist or broken, download and save to cache
func (f *cachedFetcher) Fetch(ctx context.Context, crlURL string) (bundle *cache.Bundle, fromCache bool, err error) {
	if crlURL == "" {
		return nil, false, errors.New("CRL URL is empty")
	}

	// try to get from cache
	bundle, err = f.cacheClient.Get(ctx, crlURL)
	if err != nil {
		var cacheBrokenError *cache.BrokenFileError
		if errors.Is(err, cache.ErrNotFound) ||
			errors.Is(err, cache.ErrCacheMiss) ||
			errors.As(err, &cacheBrokenError) {
			bundle, err = f.Download(ctx, crlURL)
			if err != nil {
				return nil, false, err
			}
			return bundle, false, nil
		}

		return nil, false, err
	}

	return bundle, true, nil
}

// Download downloads the CRL from the given URL and saves it to the
// cache
func (f *cachedFetcher) Download(ctx context.Context, crlURL string) (bundle *cache.Bundle, err error) {
	bundle, err = download(ctx, crlURL, f.httpClient)
	if err != nil {
		return nil, err
	}

	// save to cache
	if err := f.cacheClient.Set(ctx, crlURL, bundle); err != nil {
		return nil, fmt.Errorf("failed to save to cache: %w", err)
	}

	return bundle, nil
}

func download(ctx context.Context, crlURL string, client *http.Client) (bundle *cache.Bundle, err error) {
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}
	if len(data) == maxCRLSize {
		return nil, fmt.Errorf("CRL size exceeds the limit: %d", maxCRLSize)
	}

	// parse CRL and create bundle
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return &cache.Bundle{
		BaseCRL: crl,
		Metadata: cache.Metadata{
			BaseCRL: cache.CRLMetadata{
				URL: crlURL,
			},
			CreateAt: time.Now(),
		},
	}, nil
}
