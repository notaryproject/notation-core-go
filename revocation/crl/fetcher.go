package crl

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
)

// Fetcher is an interface to fetch CRL
type Fetcher interface {
	// Fetch retrieves the CRL with the given URL
	Fetch(ctx context.Context, url string) (crl *cache.CRL, err error)
}

// cachedFetcher is a CRL fetcher with cache
type cachedFetcher struct {
	httpClient *http.Client
	cache      cache.Cache
}

// NewCachedFetcher creates a new CRL fetcher with cache
func NewCachedFetcher(httpClient *http.Client, cache cache.Cache) Fetcher {
	return &cachedFetcher{
		httpClient: httpClient,
		cache:      cache,
	}
}

// Fetch retrieves the CRL with the given URL
func (c *cachedFetcher) Fetch(ctx context.Context, url string) (crl *cache.CRL, err error) {
	fmt.Println("fetching CRL from", url)
	// try to get from cache
	obj, err := c.cache.Get(ctx, tarStoreName(url))
	if err != nil {
		if os.IsNotExist(err) {
			// fallback to fetch from remote
			crlStore, err := c.download(url)
			if err != nil {
				return nil, err
			}
			return crlStore, nil
		}

		return nil, err
	}

	crl, ok := obj.(*cache.CRL)
	if !ok {
		return nil, fmt.Errorf("invalid cache object type: %T", obj)
	}

	return crl, nil
}

func (c *cachedFetcher) download(url string) (*cache.CRL, error) {
	// fetch from remote
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, err
	}

	crlStore := cache.NewCRL(crl, url)
	return crlStore, nil
}

func tarStoreName(url string) string {
	return hashURL(url) + ".tar"
}

// hashURL hashes the URL with SHA256 and returns the hex-encoded result
func hashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}
