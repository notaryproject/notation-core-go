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

package crl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestNewHTTPFetcher(t *testing.T) {
	t.Run("httpClient is nil", func(t *testing.T) {
		_, err := NewHTTPFetcher(nil)
		if err.Error() != "httpClient cannot be nil" {
			t.Errorf("NewHTTPFetcher() error = %v, want %v", err, "httpClient cannot be nil")
		}
	})
}

func TestFetch(t *testing.T) {
	// prepare crl
	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		NextUpdate: time.Now().Add(1 * time.Hour),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}
	baseCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse base CRL: %v", err)
	}
	const exampleURL = "http://localhost.test"
	const uncachedURL = "http://uncached.test"

	bundle := &Bundle{
		BaseCRL: baseCRL,
	}

	t.Run("url is empty", func(t *testing.T) {
		c := &memoryCache{}
		httpClient := &http.Client{}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		f.Cache = c
		_, err = f.Fetch(context.Background(), "")
		if err.Error() != "CRL URL cannot be empty" {
			t.Fatalf("Fetcher.Fetch() error = %v, want CRL URL cannot be empty", err)
		}
	})

	t.Run("fetch without cache", func(t *testing.T) {
		httpClient := &http.Client{
			Transport: &expectedRoundTripperMock{Body: baseCRL.Raw},
		}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		bundle, err := f.Fetch(context.Background(), exampleURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		if !bytes.Equal(bundle.BaseCRL.Raw, baseCRL.Raw) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", bundle.BaseCRL.Raw, baseCRL.Raw)
		}
	})

	t.Run("cache hit", func(t *testing.T) {
		// set the cache
		c := &memoryCache{}
		if err := c.Set(context.Background(), exampleURL, bundle); err != nil {
			t.Errorf("Cache.Set() error = %v, want nil", err)
		}

		httpClient := &http.Client{}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		f.Cache = c
		bundle, err := f.Fetch(context.Background(), exampleURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		if !bytes.Equal(bundle.BaseCRL.Raw, baseCRL.Raw) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", bundle.BaseCRL.Raw, baseCRL.Raw)
		}
	})

	t.Run("cache miss and download failed error", func(t *testing.T) {
		c := &memoryCache{}
		httpClient := &http.Client{
			Transport: errorRoundTripperMock{},
		}
		f, err := NewHTTPFetcher(httpClient)
		f.Cache = c
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		_, err = f.Fetch(context.Background(), uncachedURL)
		if err == nil {
			t.Errorf("Fetcher.Fetch() error = nil, want not nil")
		}
	})

	t.Run("cache miss", func(t *testing.T) {
		c := &memoryCache{}
		httpClient := &http.Client{
			Transport: &expectedRoundTripperMock{Body: baseCRL.Raw},
		}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		f.Cache = c
		f.DiscardCacheError = false
		bundle, err := f.Fetch(context.Background(), uncachedURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		if !bytes.Equal(bundle.BaseCRL.Raw, baseCRL.Raw) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", bundle.BaseCRL.Raw, baseCRL.Raw)
		}
	})

	t.Run("cache expired", func(t *testing.T) {
		c := &memoryCache{}
		// prepare an expired CRL
		certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
		expiredCRLBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(1),
			NextUpdate: time.Now().Add(-1 * time.Hour),
		}, certChain[1].Cert, certChain[1].PrivateKey)
		if err != nil {
			t.Fatalf("failed to create base CRL: %v", err)
		}
		expiredCRL, err := x509.ParseRevocationList(expiredCRLBytes)
		if err != nil {
			t.Fatalf("failed to parse base CRL: %v", err)
		}
		// store the expired CRL
		const expiredCRLURL = "http://localhost.test/expired"
		bundle := &Bundle{
			BaseCRL: expiredCRL,
		}
		if err := c.Set(context.Background(), expiredCRLURL, bundle); err != nil {
			t.Errorf("Cache.Set() error = %v, want nil", err)
		}

		// fetch the expired CRL
		httpClient := &http.Client{
			Transport: &expectedRoundTripperMock{Body: baseCRL.Raw},
		}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		f.Cache = c
		f.DiscardCacheError = true
		bundle, err = f.Fetch(context.Background(), expiredCRLURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		// should re-download the CRL
		if !bytes.Equal(bundle.BaseCRL.Raw, baseCRL.Raw) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", bundle.BaseCRL.Raw, baseCRL.Raw)
		}
	})

	t.Run("Set cache error", func(t *testing.T) {
		c := &errorCache{
			GetError: ErrCacheMiss,
			SetError: errors.New("cache error"),
		}
		httpClient := &http.Client{
			Transport: &expectedRoundTripperMock{Body: baseCRL.Raw},
		}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		f.Cache = c
		f.DiscardCacheError = true
		bundle, err = f.Fetch(context.Background(), exampleURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		if !bytes.Equal(bundle.BaseCRL.Raw, baseCRL.Raw) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", bundle.BaseCRL.Raw, baseCRL.Raw)
		}
	})

	t.Run("Get error without discard", func(t *testing.T) {
		c := &errorCache{
			GetError: errors.New("cache error"),
		}
		httpClient := &http.Client{
			Transport: &expectedRoundTripperMock{Body: baseCRL.Raw},
		}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		f.Cache = c
		f.DiscardCacheError = false
		_, err = f.Fetch(context.Background(), exampleURL)
		if !strings.HasPrefix(err.Error(), "failed to retrieve CRL from cache:") {
			t.Errorf("Fetcher.Fetch() error = %v, want failed to retrieve CRL from cache:", err)
		}
	})

	t.Run("Set error without discard", func(t *testing.T) {
		c := &errorCache{
			GetError: ErrCacheMiss,
			SetError: errors.New("cache error"),
		}
		httpClient := &http.Client{
			Transport: &expectedRoundTripperMock{Body: baseCRL.Raw},
		}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		f.Cache = c
		f.DiscardCacheError = false
		_, err = f.Fetch(context.Background(), exampleURL)
		if !strings.HasPrefix(err.Error(), "failed to store CRL to cache:") {
			t.Errorf("Fetcher.Fetch() error = %v, want failed to store CRL to cache:", err)
		}
	})

	t.Run("test fetch delta CRL from base CRL extension failed", func(t *testing.T) {
		crlWithDeltaCRL, err := os.ReadFile("testdata/crlWithMultipleFreshestCRLs.crl")
		if err != nil {
			t.Fatalf("failed to read CRL: %v", err)
		}
		httpClient := &http.Client{
			Transport: &expectedRoundTripperMock{
				Body:            crlWithDeltaCRL,
				SecondRoundBody: []byte("invalid crl"),
			},
		}
		f, err := NewHTTPFetcher(httpClient)
		if err != nil {
			t.Errorf("NewHTTPFetcher() error = %v, want nil", err)
		}
		_, err = f.Fetch(context.Background(), exampleURL)
		expectedErrorMsg := "failed to retrieve CRL: x509: malformed crl"
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected error %q, got %v", expectedErrorMsg, err)
		}
	})
}

func TestParseFreshestCRL(t *testing.T) {
	loadExtentsion := func(certPath string) pkix.Extension {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("failed to read certificate: %v", err)
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			t.Fatalf("failed to decode PEM block")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse certificate: %v", err)
		}

		for _, ext := range cert.Extensions {
			if ext.Id.Equal([]int{2, 5, 29, 46}) { // id-ce-freshestCRL
				return ext
			}
		}

		t.Fatalf("freshestCRL extension not found")
		return pkix.Extension{}
	}

	t.Run("valid 1 delta CRL URL", func(t *testing.T) {
		certPath := "testdata/certificateWithDeltaCRL.cer"
		freshestCRLExtension := loadExtentsion(certPath)
		urls, err := parseCRLDistributionPoint(freshestCRLExtension.Value)
		if err != nil {
			t.Fatalf("failed to parse freshest CRL: %v", err)
		}

		if len(urls) != 1 {
			t.Fatalf("expected 1 URL, got %d", len(urls))
		}

		if !strings.HasPrefix(urls[0], "http://localhost:80") {
			t.Fatalf("unexpected URL: %s", urls[0])
		}
	})

	t.Run("empty extension", func(t *testing.T) {
		_, err := parseCRLDistributionPoint(nil)
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("URL doesn't exist", func(t *testing.T) {
		certPath := "testdata/certificateWithZeroDeltaCRLURL.cer"
		freshestCRLExtension := loadExtentsion(certPath)
		url, err := parseCRLDistributionPoint(freshestCRLExtension.Value)
		if err != nil {
			t.Fatalf("failed to parse freshest CRL: %v", err)
		}
		if len(url) != 0 {
			t.Fatalf("expected 0 URL, got %d", len(url))
		}
	})

	t.Run("non URI freshest CRL extension", func(t *testing.T) {
		certPath := "testdata/certificateWithNonURIDeltaCRL.cer"
		freshestCRLExtension := loadExtentsion(certPath)
		url, err := parseCRLDistributionPoint(freshestCRLExtension.Value)
		if err != nil {
			t.Fatalf("failed to parse freshest CRL: %v", err)
		}
		if len(url) != 0 {
			t.Fatalf("expected 0 URL, got %d", len(url))
		}
	})

	t.Run("certificate with incomplete freshest CRL extension", func(t *testing.T) {
		certPath := "testdata/certificateWithIncompleteFreshestCRL.cer"
		freshestCRLExtension := loadExtentsion(certPath)
		_, err := parseCRLDistributionPoint(freshestCRLExtension.Value)
		expectErrorMsg := "x509: invalid CRL distribution point"
		if err == nil || err.Error() != expectErrorMsg {
			t.Fatalf("expected error %q, got %v", expectErrorMsg, err)
		}
	})

	t.Run("certificate with incomplete freshest CRL extension2", func(t *testing.T) {
		certPath := "testdata/certificateWithIncompleteFreshestCRL2.cer"
		freshestCRLExtension := loadExtentsion(certPath)
		url, err := parseCRLDistributionPoint(freshestCRLExtension.Value)
		if err != nil {
			t.Fatalf("failed to parse freshest CRL: %v", err)
		}
		if len(url) != 0 {
			t.Fatalf("expected 0 URL, got %d", len(url))
		}
	})
}

func TestFetchDeltaCRL(t *testing.T) {
	loadExtentsion := func(certPath string) []pkix.Extension {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("failed to read certificate: %v", err)
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			t.Fatalf("failed to decode PEM block")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse certificate: %v", err)
		}

		return cert.Extensions
	}

	deltaCRL, err := os.ReadFile("testdata/delta.crl")
	if err != nil {
		t.Fatalf("failed to read delta CRL: %v", err)
	}

	fetcher, err := NewHTTPFetcher(&http.Client{
		Transport: &expectedRoundTripperMock{Body: deltaCRL},
	})
	if err != nil {
		t.Fatalf("failed to create fetcher: %v", err)
	}

	t.Run("parse freshest CRL failed", func(t *testing.T) {
		certPath := "testdata/certificateWithIncompleteFreshestCRL.cer"
		extensions := loadExtentsion(certPath)
		_, err := fetcher.fetchDeltaCRL(context.Background(), extensions)
		expectedErrorMsg := "failed to parse Freshest CRL extension: x509: invalid CRL distribution point"
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected error %q, got %v", expectedErrorMsg, err)
		}
	})

	t.Run("zero freshest CRL URL", func(t *testing.T) {
		certPath := "testdata/certificateWithZeroDeltaCRLURL.cer"
		extensions := loadExtentsion(certPath)
		_, err := fetcher.fetchDeltaCRL(context.Background(), extensions)
		expectedErr := errDeltaCRLNotFound
		if err == nil || !errors.Is(err, expectedErr) {
			t.Fatalf("expected error %v, got %v", expectedErr, err)
		}
	})

	t.Run("one freshest CRL URL", func(t *testing.T) {
		certPath := "testdata/certificateWithDeltaCRL.cer"
		extensions := loadExtentsion(certPath)
		deltaCRL, err := fetcher.fetchDeltaCRL(context.Background(), extensions)
		if err != nil {
			t.Fatalf("failed to process delta CRL: %v", err)
		}
		if deltaCRL == nil {
			t.Fatalf("expected non-nil delta CRL")
		}
	})

	t.Run("multiple freshest CRL URLs failed", func(t *testing.T) {
		fetcherWithError, err := NewHTTPFetcher(&http.Client{
			Transport: errorRoundTripperMock{},
		})
		if err != nil {
			t.Fatalf("failed to create fetcher: %v", err)
		}
		certPath := "testdata/certificateWith2DeltaCRL.cer"
		extensions := loadExtentsion(certPath)
		_, err = fetcherWithError.fetchDeltaCRL(context.Background(), extensions)
		expectedErrorMsg := "request failed"
		if err == nil || !strings.Contains(err.Error(), expectedErrorMsg) {
			t.Fatalf("expected error %q, got %v", expectedErrorMsg, err)
		}
	})

	t.Run("process delta crl from certificate extension failed", func(t *testing.T) {
		certPath := "testdata/certificateWithIncompleteFreshestCRL.cer"
		extensions := loadExtentsion(certPath)
		_, err := fetcher.fetchDeltaCRL(context.Background(), extensions)
		expectedErrorMsg := "failed to parse Freshest CRL extension: x509: invalid CRL distribution point"
		if err == nil || err.Error() != expectedErrorMsg {
			t.Fatalf("expected error %q, got %v", expectedErrorMsg, err)
		}
	})
}

func TestDownload(t *testing.T) {
	t.Run("parse url error", func(t *testing.T) {
		_, err := fetchCRL(context.Background(), ":", http.DefaultClient)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("https download", func(t *testing.T) {
		_, err := fetchCRL(context.Background(), "https://localhost.test", http.DefaultClient)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("http.NewRequestWithContext error", func(t *testing.T) {
		var ctx context.Context = nil
		_, err := fetchCRL(ctx, "http://localhost.test", &http.Client{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("client.Do error", func(t *testing.T) {
		_, err := fetchCRL(context.Background(), "http://localhost.test", &http.Client{
			Transport: errorRoundTripperMock{},
		})

		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("status code is not 2xx", func(t *testing.T) {
		_, err := fetchCRL(context.Background(), "http://localhost.test", &http.Client{
			Transport: serverErrorRoundTripperMock{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("readAll error", func(t *testing.T) {
		_, err := fetchCRL(context.Background(), "http://localhost.test", &http.Client{
			Transport: readFailedRoundTripperMock{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("exceed the size limit", func(t *testing.T) {
		_, err := fetchCRL(context.Background(), "http://localhost.test", &http.Client{
			Transport: &expectedRoundTripperMock{Body: make([]byte, maxCRLSize+1)},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid crl", func(t *testing.T) {
		_, err := fetchCRL(context.Background(), "http://localhost.test", &http.Client{
			Transport: &expectedRoundTripperMock{Body: []byte("invalid crl")},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

type errorRoundTripperMock struct{}

func (rt errorRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("error")
}

type serverErrorRoundTripperMock struct{}

func (rt serverErrorRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Request:    req,
		StatusCode: http.StatusInternalServerError,
	}, nil
}

type readFailedRoundTripperMock struct{}

func (rt readFailedRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       errorReaderMock{},
	}, nil
}

type errorReaderMock struct{}

func (r errorReaderMock) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("error")
}

func (r errorReaderMock) Close() error {
	return nil
}

type expectedRoundTripperMock struct {
	Body            []byte
	SecondRoundBody []byte
	count           int
}

func (rt *expectedRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.count == 0 {
		rt.count += 1
		return &http.Response{
			Request:    req,
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(rt.Body)),
		}, nil
	}
	return &http.Response{
		Request:    req,
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(rt.SecondRoundBody)),
	}, nil
}

// memoryCache is an in-memory cache that stores CRL bundles for testing.
type memoryCache struct {
	store sync.Map
}

// Get retrieves the CRL from the memory store.
//
// - if the key does not exist, return ErrNotFound
// - if the CRL is expired, return ErrCacheMiss
func (c *memoryCache) Get(ctx context.Context, url string) (*Bundle, error) {
	value, ok := c.store.Load(url)
	if !ok {
		return nil, ErrCacheMiss
	}
	bundle, ok := value.(*Bundle)
	if !ok {
		return nil, fmt.Errorf("invalid type: %T", value)
	}

	return bundle, nil
}

// Set stores the CRL in the memory store.
func (c *memoryCache) Set(ctx context.Context, url string, bundle *Bundle) error {
	c.store.Store(url, bundle)
	return nil
}

type errorCache struct {
	GetError error
	SetError error
}

func (c *errorCache) Get(ctx context.Context, url string) (*Bundle, error) {
	return nil, c.GetError
}

func (c *errorCache) Set(ctx context.Context, url string, bundle *Bundle) error {
	return c.SetError
}
