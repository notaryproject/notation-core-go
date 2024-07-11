package crl

import (
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"time"
)

// CRLFetcher is an interface to fetch CRL
type CRLFetcher interface {
	// Fetch retrieves the CRL with the given URL
	Fetch(url string) (CRLStore, error)
}

type cachedCRLFetcher struct {
	httpClient *http.Client
	cache      Cache
}

// NewCachedCRLFetcher creates a new CRL fetcher with cache
func NewCachedCRLFetcher(httpClient *http.Client, cache Cache) CRLFetcher {
	return &cachedCRLFetcher{
		httpClient: httpClient,
		cache:      cache,
	}
}

func (c *cachedCRLFetcher) Fetch(url string) (CRLStore, error) {
	// try to get from cache
	file, err := c.cache.Get(url)
	if err != nil {
		if os.IsNotExist(err) {
			// fallback to fetch from remote
			return c.download(url)
		}

		return nil, err
	}
	defer file.Close()

	crlStore, err := ParseCRLTar(file)
	if err != nil {
		return c.download(url)
	}

	if crlStore.baseCRL.NextUpdate.Before(time.Now()) {
		// cache is expired
		return c.download(url)
	}

	return crlStore, nil
}

func (c *cachedCRLFetcher) download(url string) (CRLStore, error) {
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

	crlStore := NewCRLTarStore(crl, url, c.cache)
	return crlStore, nil
}
