package crl

import (
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"time"
)

// CRLClient is an interface to fetch CRL
type CRLClient interface {
	// Fetch retrieves the CRL with the given URL from remote or local cache
	Fetch(url string) (*x509.RevocationList, error)
}

type crlClient struct {
	cache      Cache
	httpClient *http.Client
}

// NewCRLClient creates a new CRL server
func NewCRLClient(cache Cache, httpClient *http.Client) CRLClient {
	return &crlClient{
		cache:      cache,
		httpClient: httpClient,
	}
}

func (c *crlClient) Fetch(url string) (*x509.RevocationList, error) {
	// try to get from cache
	data, err := c.cache.Get(url)
	if err != nil {
		if os.IsNotExist(err) {
			// fallback to fetch from remote
			return c.update(url)
		}

		return nil, err
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, err
	}

	if crl.NextUpdate.Before(time.Now()) {
		// cache is expired, update
		return c.update(url)
	}

	return crl, nil
}

func (c *crlClient) update(url string) (*x509.RevocationList, error) {
	// fetch from remote
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the CRL file
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// store in cache
	if err := c.cache.Set(url, data); err != nil {
		return nil, err
	}

	return x509.ParseRevocationList(data)
}
