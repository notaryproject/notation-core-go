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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
	"github.com/notaryproject/notation-core-go/revocation/internal/cachehelper"
	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestNewHTTPFetcher(t *testing.T) {
	t.Run("httpClient is nil", func(t *testing.T) {
		_ = NewHTTPFetcher(nil)
	})
}

func TestFetch(t *testing.T) {
	// prepare cache
	c := cachehelper.NewMemoryCache()

	// prepare crl
	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}
	baseCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		t.Fatalf("failed to parse base CRL: %v", err)
	}
	const exampleURL = "http://example.com"
	const uncachedURL = "http://uncached.com"

	bundle := &cache.Bundle{
		BaseCRL: baseCRL,
		Metadata: cache.Metadata{
			BaseCRL: cache.CRLMetadata{
				URL: exampleURL,
			},
			CachedAt: time.Now(),
		},
	}
	if err := c.Set(context.Background(), exampleURL, bundle); err != nil {
		t.Errorf("Cache.Set() error = %v, want nil", err)
	}

	t.Run("url is empty", func(t *testing.T) {
		f := NewHTTPFetcher(nil)
		f.Cache = c
		_, _, err = f.Fetch(context.Background(), "")
		if err == nil {
			t.Errorf("Fetcher.Fetch() error = nil, want not nil")
		}
	})

	t.Run("fetch without cache", func(t *testing.T) {
		httpClient := &http.Client{
			Transport: expectedRoundTripperMock{Body: baseCRL.Raw},
		}
		f := NewHTTPFetcher(httpClient)
		base, _, err := f.Fetch(context.Background(), exampleURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		if !bytes.Equal(base.Raw, baseCRL.Raw) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", base.Raw, baseCRL.Raw)
		}
	})

	t.Run("cache hit", func(t *testing.T) {
		f := NewHTTPFetcher(nil)
		f.Cache = c
		base, _, err := f.Fetch(context.Background(), exampleURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		if !bytes.Equal(base.Raw, baseCRL.Raw) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", base.Raw, baseCRL.Raw)
		}
	})

	t.Run("cache miss", func(t *testing.T) {
		httpClient := &http.Client{
			Transport: expectedRoundTripperMock{Body: baseCRL.Raw},
		}
		f := NewHTTPFetcher(httpClient)
		f.Cache = c
		base, _, err := f.Fetch(context.Background(), uncachedURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		if !bytes.Equal(base.Raw, baseCRL.Raw) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", base.Raw, baseCRL.Raw)
		}
	})

	t.Run("cache miss and download failed error", func(t *testing.T) {
		httpClient := &http.Client{
			Transport: errorRoundTripperMock{},
		}
		f := NewHTTPFetcher(httpClient)
		_, _, err = f.Fetch(context.Background(), uncachedURL)
		if err == nil {
			t.Errorf("Fetcher.Fetch() error = nil, want not nil")
		}
	})

	t.Run("cache expired", func(t *testing.T) {
		expiredBundle := &cache.Bundle{
			BaseCRL: baseCRL,
			Metadata: cache.Metadata{
				BaseCRL: cache.CRLMetadata{
					URL:        exampleURL,
					NextUpdate: time.Now().Add(-1 * time.Hour),
				},
				CachedAt: time.Now().Add(-1 * time.Hour),
			},
		}
		if err := c.Set(context.Background(), exampleURL, expiredBundle); err != nil {
			t.Errorf("Cache.Set() error = %v, want nil", err)
		}

		// generate a new CRL
		// prepare crl
		certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
		newCRLBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1),
		}, certChain[1].Cert, certChain[1].PrivateKey)
		if err != nil {
			t.Fatalf("failed to create base CRL: %v", err)
		}

		httpClient := &http.Client{
			Transport: expectedRoundTripperMock{Body: newCRLBytes},
		}
		f := NewHTTPFetcher(httpClient)
		f.Cache = c
		base, _, err := f.Fetch(context.Background(), exampleURL)
		if err != nil {
			t.Errorf("Fetcher.Fetch() error = %v, want nil", err)
		}
		if !bytes.Equal(base.Raw, newCRLBytes) {
			t.Errorf("Fetcher.Fetch() base.Raw = %v, want %v", base.Raw, baseCRL.Raw)
		}
	})
}

func TestDownload(t *testing.T) {
	t.Run("parse url error", func(t *testing.T) {
		_, err := download(context.Background(), ":", http.DefaultClient)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("https download", func(t *testing.T) {
		_, err := download(context.Background(), "https://example.com", http.DefaultClient)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("http.NewRequestWithContext error", func(t *testing.T) {
		var ctx context.Context = nil
		_, err := download(ctx, "http://example.com", &http.Client{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("client.Do error", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: errorRoundTripperMock{},
		})

		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("status code is not 2xx", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: serverErrorRoundTripperMock{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("readAll error", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: readFailedRoundTripperMock{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("exceed the size limit", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: expectedRoundTripperMock{Body: make([]byte, MaxCRLSize+1)},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid crl", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: expectedRoundTripperMock{Body: []byte("invalid crl")},
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
	Body []byte
}

func (rt expectedRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Request:    req,
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(rt.Body)),
	}, nil
}
