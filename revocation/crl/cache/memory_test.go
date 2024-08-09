package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryCache(t *testing.T) {
	ctx := context.Background()

	// Test NewMemoryCache
	opts := MemoryCacheOptions{MaxAge: 5 * time.Minute}
	cache, err := NewMemoryCache(opts)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cache.(*memoryCache).maxAge != opts.MaxAge {
		t.Fatalf("expected maxAge %v, got %v", opts.MaxAge, cache.(*memoryCache).maxAge)
	}

	bundle := &Bundle{Metadata: Metadata{CreateAt: time.Now()}}
	key := "testKey"
	t.Run("SetAndGet", func(t *testing.T) {
		if err := cache.Set(ctx, key, bundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		retrievedBundle, err := cache.Get(ctx, key)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if retrievedBundle != bundle {
			t.Fatalf("expected bundle %v, got %v", bundle, retrievedBundle)
		}
	})

	t.Run("GetWithExpiredBundle", func(t *testing.T) {
		expiredBundle := &Bundle{Metadata: Metadata{CreateAt: time.Now().Add(-10 * time.Minute)}}
		if err := cache.Set(ctx, "expiredKey", expiredBundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = cache.Get(ctx, "expiredKey")
		if _, ok := err.(*ExpiredError); !ok {
			t.Fatalf("expected CacheExpiredError, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := cache.Delete(ctx, key); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = cache.Get(ctx, key)
		if _, ok := err.(*NotExistError); !ok {
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
		_, err = cache.Get(ctx, "key1")
		if _, ok := err.(*NotExistError); !ok {
			t.Fatalf("expected error, got nil")
		}
		_, err = cache.Get(ctx, "key2")
		if _, ok := err.(*NotExistError); !ok {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestMemoryCacheFailed(t *testing.T) {
	ctx := context.Background()

	// Test Get with invalid type
	cache, err := NewMemoryCache(MemoryCacheOptions{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	cache.(*memoryCache).store.Store("invalidKey", "invalidValue")
	_, err = cache.Get(ctx, "invalidKey")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
