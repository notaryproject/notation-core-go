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
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryCache(t *testing.T) {
	ctx := context.Background()

	// Test NewMemoryCache
	cache, err := NewMemoryCache()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cache.MaxAge != DefaultMaxAge {
		t.Fatalf("expected maxAge %v, got %v", DefaultMaxAge, cache.MaxAge)
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
		expiredBundle := &Bundle{Metadata: Metadata{CreateAt: time.Now().Add(-DefaultMaxAge - 1*time.Second)}}
		if err := cache.Set(ctx, "expiredKey", expiredBundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = cache.Get(ctx, "expiredKey")
		if !errors.Is(err, ErrCacheMiss) {
			t.Fatalf("expected ErrCacheMiss, got %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		if err := cache.Delete(ctx, key); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = cache.Get(ctx, key)
		if !errors.Is(err, ErrNotFound) {
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
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected error, got nil")
		}
		_, err = cache.Get(ctx, "key2")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("Cache interface", func(t *testing.T) {
		var _ Cache = cache
	})
}

func TestMemoryCacheFailed(t *testing.T) {
	ctx := context.Background()

	// Test Get with invalid type
	cache, err := NewMemoryCache()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	cache.store.Store("invalidKey", "invalidValue")
	_, err = cache.Get(ctx, "invalidKey")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}
