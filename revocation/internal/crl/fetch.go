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
	"time"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
)

// maxCRLSize is the maximum size of CRL in bytes
const maxCRLSize = 64 * 1024 * 1024 // 64 MiB

func fetch(ctx context.Context, c cache.Cache, crlURL string, cacheMaxAge time.Duration, httpClient *http.Client) (*cache.Bundle, error) {
	if c == nil {
		return download(ctx, crlURL, httpClient)
	}

	// try to get from cache
	crlBundle, err := c.Get(ctx, tarStoreName(crlURL), cacheMaxAge)
	if err != nil {
		var cacheBrokenError *cache.BrokenFileError
		if os.IsNotExist(err) || errors.As(err, &cacheBrokenError) {
			// download if not exist or broken
			return download(ctx, crlURL, httpClient)
		}
		return nil, err
	}

	return crlBundle, nil
}

func download(ctx context.Context, crlURL string, client *http.Client) (*cache.Bundle, error) {
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

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}
	return cache.NewBundle(crl, crlURL)
}

func tarStoreName(url string) string {
	return hashURL(url) + ".tar"
}

// hashURL hashes the URL with SHA256 and returns the hex-encoded result
func hashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}
