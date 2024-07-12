package crl

import (
	"crypto/x509"
	"io"
	"net/http"
	"os"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
)

// CRLFetcher is an interface to fetch CRL
type CRLFetcher interface {
	// Fetch retrieves the CRL with the given URL
	Fetch(url string) (crlStore CRLStore, cached bool, err error)
}

type cachedCRLFetcher struct {
	httpClient *http.Client
	cache      cache.Cache
}

// NewCachedCRLFetcher creates a new CRL fetcher with cache
func NewCachedCRLFetcher(httpClient *http.Client, cache cache.Cache) CRLFetcher {
	return &cachedCRLFetcher{
		httpClient: httpClient,
		cache:      cache,
	}
}

func (c *cachedCRLFetcher) Fetch(url string) (crlStore CRLStore, cached bool, err error) {
	// try to get from cache
	file, err := c.cache.Get(url)
	if err != nil {
		if os.IsNotExist(err) {
			// fallback to fetch from remote
			crlStore, err := c.download(url)
			if err != nil {
				return nil, false, err
			}
			return crlStore, cached, nil
		}

		return nil, false, err
	}
	defer file.Close()

	crlStore, err = ParseCRLTar(file)
	if err != nil {
		crlStore, err := c.download(url)
		if err != nil {
			return nil, false, err
		}
		return crlStore, cached, nil
	}

	cached = true
	return crlStore, cached, nil
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
