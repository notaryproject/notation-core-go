package crl

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

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
	startTime := time.Now()
	// try to get from cache
	file, err := c.cache.Get(buildTarName(url))
	if err != nil {
		if os.IsNotExist(err) {
			// fallback to fetch from remote
			crlStore, err := c.download(url)
			if err != nil {
				return nil, false, err
			}
			return crlStore, false, nil
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
		return crlStore, false, nil
	}

	// Calculate the duration
	duration := time.Since(startTime)
	fmt.Printf("The cache request to %s took %s\n", url, duration)

	return crlStore, true, nil
}

func (c *cachedCRLFetcher) download(url string) (CRLStore, error) {
	fmt.Println("downloading CRL from", url)
	startTime := time.Now()
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

	// Calculate the duration
	duration := time.Since(startTime)

	fmt.Printf("The HTTP request took %s\n", duration)

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, err
	}

	crlStore := NewCRLTarStore(crl, url, c.cache)
	return crlStore, nil
}
