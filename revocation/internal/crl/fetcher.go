package crl

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
)

// maxCRLSize is the maximum size of CRL in bytes
const maxCRLSize = 64 * 1024 * 1024 // 64 MiB

// Fetcher is an interface that specifies methods used for fetching CRL
// from the given URL
//
// The interface is useful for pre-loading CRLs cache before the verification
type Fetcher interface {
	Fetch(ctx context.Context, crlURL string) (bundle *cache.Bundle, fromCache bool, err error)
}

type fetcher struct {
	httpClient  *http.Client
	cacheClient cache.Cache
}

// NewFetcher creates a new Fetcher with the given HTTP client and cache client
//   - if httpClient is nil, http.DefaultClient will be used
//   - if cacheClient is nil, no cache will be used
func NewFetcher(httpClient *http.Client, cacheClient cache.Cache) Fetcher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &fetcher{
		httpClient:  httpClient,
		cacheClient: cacheClient,
	}
}

// Fetch retrieves the CRL from the given URL
//   - if the cache is enabled, it will try to get the CRL from the cache first
//   - if the CRL is not in the cache or expired, it will download the CRL from
//     the URL
func (f *fetcher) Fetch(ctx context.Context, crlURL string) (bundle *cache.Bundle, fromCache bool, err error) {
	if crlURL == "" {
		return nil, false, errors.New("CRL URL is empty")
	}

	if f.cacheClient == nil {
		// no cache, download directly
		return f.downloadAndCache(ctx, crlURL)
	}

	// try to get from cache
	bundle, err = f.cacheClient.Get(ctx, tarStoreName(crlURL))
	if err != nil {
		var cacheBrokenError *cache.BrokenFileError
		if os.IsNotExist(err) || errors.As(err, &cacheBrokenError) {
			// download if not exist or broken
			return f.downloadAndCache(ctx, crlURL)
		}
		return nil, false, err
	}

	return bundle, true, nil
}

func (f *fetcher) downloadAndCache(ctx context.Context, crlURL string) (bundle *cache.Bundle, fromCache bool, err error) {
	bundle, err = download(ctx, crlURL, f.httpClient)
	if err != nil {
		return nil, false, err
	}

	// save to cache
	if err := f.cacheClient.Set(ctx, tarStoreName(crlURL), bundle); err != nil {
		return nil, false, fmt.Errorf("failed to save to cache: %w", err)
	}

	return bundle, false, nil
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
	limitedReader := io.LimitReader(resp.Body, maxCRLSize)
	data, err := io.ReadAll(limitedReader)
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
	bundle, err = cache.NewBundle(crl, crlURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle: %w", err)
	}
	return bundle, nil
}

func tarStoreName(url string) string {
	return hashURL(url) + ".tar"
}

// hashURL hashes the URL with SHA256 and returns the hex-encoded result
func hashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}
