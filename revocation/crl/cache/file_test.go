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

package cache

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestFileCache(t *testing.T) {
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

	ctx := context.Background()
	root := t.TempDir()
	cache, err := NewFileCache(root)
	t.Run("NewFileCache", func(t *testing.T) {
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cache.root != root {
			t.Fatalf("expected dir %v, got %v", root, cache.root)
		}
		if cache.MaxAge != DefaultMaxAge {
			t.Fatalf("expected maxAge %v, got %v", DefaultMaxAge, cache.MaxAge)
		}
	})

	key := "testKey"
	bundle := &Bundle{BaseCRL: baseCRL, Metadata: Metadata{BaseCRL: CRLMetadata{URL: "http://crl"}, CreateAt: time.Now()}}
	t.Run("SetAndGet", func(t *testing.T) {
		if err := cache.Set(ctx, key, bundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		retrievedBundle, err := cache.Get(ctx, key)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if retrievedBundle.Metadata.CreateAt.Unix() != bundle.Metadata.CreateAt.Unix() {
			t.Fatalf("expected bundle %v, got %v", bundle, retrievedBundle)
		}
	})

	t.Run("GetWithExpiredBundle", func(t *testing.T) {
		expiredBundle := &Bundle{BaseCRL: baseCRL, Metadata: Metadata{BaseCRL: CRLMetadata{URL: "http://crl"}, CreateAt: time.Now().Add(-DefaultMaxAge - 1*time.Second)}}
		if err := cache.Set(ctx, "expiredKey", expiredBundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = cache.Get(ctx, "expiredKey")
		if !errors.Is(err, ErrCacheMiss) {
			t.Fatalf("expected ErrCacheMiss, got %v", err)
		}
	})

	t.Run("Cache interface", func(t *testing.T) {
		var _ Cache = cache
	})
}

func TestNewFileCache(t *testing.T) {
	tempDir := t.TempDir()
	t.Run("without permission to create cache directory", func(t *testing.T) {
		if err := os.Chmod(tempDir, 0); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
		root := filepath.Join(tempDir, "test")
		_, err := NewFileCache(root)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		// restore permission
		if err := os.Chmod(tempDir, 0755); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
	})

	t.Run("no maxAge", func(t *testing.T) {
		cache, err := NewFileCache(t.TempDir())
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cache.MaxAge != DefaultMaxAge {
			t.Fatalf("expected maxAge %v, got %v", DefaultMaxAge, cache.MaxAge)
		}
	})
}

func TestGetFailed(t *testing.T) {
	tempDir := t.TempDir()
	// write an invalid tarball
	invalidTarball := filepath.Join(tempDir, "invalid.tar")
	if err := os.WriteFile(invalidTarball, []byte("invalid tarball"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	cache, err := NewFileCache(tempDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	t.Run("invalid tarball", func(t *testing.T) {
		_, err := cache.Get(context.Background(), "invalid.tar")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("no permission to read file", func(t *testing.T) {
		if err := os.Chmod(tempDir, 0); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
		_, err := cache.Get(context.Background(), "invalid.tar")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		// restore permission
		if err := os.Chmod(tempDir, 0755); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
	})

	t.Run("invalid bundle file", func(t *testing.T) {
		bundle := &Bundle{
			BaseCRL:  &x509.RevocationList{Raw: []byte("invalid crl")},
			Metadata: Metadata{CreateAt: time.Now()},
		}
		if err := saveTar(&bytes.Buffer{}, bundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if err := os.WriteFile(filepath.Join(tempDir, fileName("invalid")), []byte("invalid tarball"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
		_, err = cache.Get(context.Background(), "invalid")
		if !strings.Contains(err.Error(), "failed to read tarball") {
			t.Fatalf("expected error, got %v", err)
		}
	})
}

func TestSetFailed(t *testing.T) {
	tempDir := t.TempDir()
	cache, err := NewFileCache(tempDir)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	t.Run("failed to save tarball", func(t *testing.T) {
		bundle := &Bundle{Metadata: Metadata{CreateAt: time.Now()}}
		if err := cache.Set(context.Background(), "invalid.tar", bundle); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestParseAndSave(t *testing.T) {
	const exampleURL = "https://example.com/base.crl"
	var buf bytes.Buffer

	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}
	t.Run("SaveAsTarball", func(t *testing.T) {
		// Create a tarball
		baseCRL, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatalf("failed to parse base CRL: %v", err)
		}
		bundle := &Bundle{
			BaseCRL: baseCRL,
			Metadata: Metadata{
				BaseCRL: CRLMetadata{
					URL: exampleURL,
				},
				CreateAt: time.Now(),
			},
		}

		if err := saveTar(&buf, bundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("ParseBundleFromTarball", func(t *testing.T) {
		// Parse the tarball
		bundle, err := parseBundleFromTar(&buf)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !bytes.Equal(crlBytes, bundle.BaseCRL.Raw) {
			t.Errorf("expected BaseCRL to be %v, got %v", crlBytes, bundle.BaseCRL.Raw)
		}

		if bundle.Metadata.BaseCRL.URL != exampleURL {
			t.Errorf("expected URL to be %s, got %s", exampleURL, bundle.Metadata.BaseCRL.URL)
		}

		if bundle.Metadata.CreateAt.IsZero() {
			t.Errorf("expected CreateAt to be set, got zero value")
		}
	})
}

func TestBundleParseFailed(t *testing.T) {
	t.Run("IO read error", func(t *testing.T) {
		_, err := parseBundleFromTar(&errorReader{})
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("missing baseCRL content (only has baseCRL header in tarball)", func(t *testing.T) {
		var buf bytes.Buffer
		header := &tar.Header{
			Name:    "base.crl",
			Size:    10,
			Mode:    0644,
			ModTime: time.Now(),
		}
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Close()

		_, err := parseBundleFromTar(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("broken baseCRL", func(t *testing.T) {
		var buf bytes.Buffer
		header := &tar.Header{
			Name:    "base.crl",
			Size:    10,
			Mode:    0644,
			ModTime: time.Now(),
		}
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write([]byte("broken crl"))
		tw.Close()

		_, err := parseBundleFromTar(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("malformed metadata", func(t *testing.T) {
		var buf bytes.Buffer
		header := &tar.Header{
			Name:    "metadata.json",
			Size:    10,
			Mode:    0644,
			ModTime: time.Now(),
		}
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write([]byte("malformed json"))
		tw.Close()

		_, err := parseBundleFromTar(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestSaveTarFailed(t *testing.T) {
	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}

	t.Run("write base CRL to tarball failed", func(t *testing.T) {
		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatalf("failed to parse base CRL: %v", err)
		}
		bundle := &Bundle{
			BaseCRL: crl,
			Metadata: Metadata{
				BaseCRL: CRLMetadata{
					URL: "https://example.com/base.crl",
				},
				CreateAt: time.Now(),
			},
		}
		if err := saveTar(&errorWriter{}, bundle); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

type errorReader struct{}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, os.ErrNotExist
}

type errorWriter struct {
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	return 0, os.ErrNotExist
}
