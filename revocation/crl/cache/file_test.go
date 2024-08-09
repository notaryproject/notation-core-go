package cache

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"path/filepath"
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
	dir := t.TempDir()
	opts := &FileCacheOptions{Dir: dir, MaxAge: 5 * time.Minute}
	cache, err := NewFileCache(opts)
	t.Run("NewFileCache", func(t *testing.T) {
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cache.(*fileCache).dir != opts.Dir {
			t.Fatalf("expected dir %v, got %v", opts.Dir, cache.(*fileCache).dir)
		}
		if cache.(*fileCache).maxAge != opts.MaxAge {
			t.Fatalf("expected maxAge %v, got %v", opts.MaxAge, cache.(*fileCache).maxAge)
		}
	})

	key := "testKey"
	bundle := &Bundle{BaseCRL: baseCRL, Metadata: Metadata{BaseCRL: FileInfo{URL: "http://crl"}, CreateAt: time.Now()}}
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
		expiredBundle := &Bundle{BaseCRL: baseCRL, Metadata: Metadata{BaseCRL: FileInfo{URL: "http://crl"}, CreateAt: time.Now().Add(-10 * time.Minute)}}
		if err := cache.Set(ctx, "expiredKey", expiredBundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = cache.Get(ctx, "expiredKey")
		if _, ok := err.(*ExpiredError); !ok {
			t.Fatalf("expected CacheExpiredError, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		// Test Delete
		if err := cache.Delete(ctx, key); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = cache.Get(ctx, key)
		var notExistError *NotExistError
		if !errors.As(err, &notExistError) {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("Flush", func(t *testing.T) {
		if err := cache.Set(ctx, "key1", bundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if err := cache.Set(ctx, "key2", bundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if err := cache.Flush(ctx); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		var notExistError *NotExistError
		_, err = cache.Get(ctx, "key1")
		if !errors.As(err, &notExistError) {
			t.Fatalf("expected error, got nil")
		}
		_, err = cache.Get(ctx, "key2")
		if !errors.As(err, &notExistError) {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestNewFileCache(t *testing.T) {
	tempDir := t.TempDir()
	t.Run("without permission to create cache directory", func(t *testing.T) {
		if err := os.Chmod(tempDir, 0); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
		_, err := NewFileCache(&FileCacheOptions{Dir: filepath.Join(tempDir, "test")})
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		// restore permission
		if err := os.Chmod(tempDir, 0755); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
	})

	t.Run("no maxAge", func(t *testing.T) {
		cache, err := NewFileCache(&FileCacheOptions{Dir: tempDir})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cache.(*fileCache).maxAge != DefaultMaxAge {
			t.Fatalf("expected maxAge %v, got %v", DefaultMaxAge, cache.(*fileCache).maxAge)
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

	cache, err := NewFileCache(&FileCacheOptions{Dir: tempDir})
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
}

func TestSetFailed(t *testing.T) {
	tempDir := t.TempDir()
	cache, err := NewFileCache(&FileCacheOptions{Dir: tempDir})
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

func TestFlushFailed(t *testing.T) {
	tempDir := t.TempDir()
	cache, err := NewFileCache(&FileCacheOptions{Dir: tempDir})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	t.Run("failed to remove files", func(t *testing.T) {
		if err := os.Chmod(tempDir, 0); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
		if err := cache.Flush(context.Background()); err == nil {
			t.Fatalf("expected error, got nil")
		}
		// restore permission
		if err := os.Chmod(tempDir, 0755); err != nil {
			t.Fatalf("failed to change permission: %v", err)
		}
	})
}
