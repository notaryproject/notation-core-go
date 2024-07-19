package crl

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
)

// Fetcher is an interface to fetch CRL
type Fetcher interface {
	// Fetch retrieves the CRL with the given URL
	Fetch(url string) (crlStore Store, err error)
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
func (c *cachedFetcher) Fetch(url string) (crlStore Store, err error) {
	fmt.Println("fetching CRL from", url)
	// try to get from cache
	file, err := c.cache.Get(tarStoreName(url))
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
	defer file.Close()

	crlStore, err = ParseTarStore(file)
	if err != nil {
		crlStore, err := c.download(url)
		if err != nil {
			return nil, err
		}
		return crlStore, nil
	}

	return crlStore, nil
}

func (c *cachedFetcher) download(url string) (Store, error) {
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

	crlStore := NewTarStore(crl, url, c.cache)
	return crlStore, nil
}
