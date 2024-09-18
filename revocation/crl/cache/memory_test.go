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
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestMemoryCache(t *testing.T) {
	ctx := context.Background()

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

	// Test NewMemoryCache
	cache := NewMemoryCache()
	if cache.MaxAge != DefaultMaxAge {
		t.Fatalf("expected maxAge %v, got %v", DefaultMaxAge, cache.MaxAge)
	}

	bundle := &Bundle{
		BaseCRL: baseCRL,
		Metadata: Metadata{
			CachedAt: time.Now(),
			BaseCRL: CRLMetadata{
				URL: "http://crl",
			},
		}}
	key := "testKey"
	t.Run("SetAndGet comformance test", func(t *testing.T) {
		if err := cache.Set(ctx, key, bundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		retrievedBundle, err := cache.Get(ctx, key)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !reflect.DeepEqual(bundle, retrievedBundle) {
			t.Fatalf("expected bundle %v, got %v", bundle, retrievedBundle)
		}
	})

	t.Run("GetWithExpiredBundle", func(t *testing.T) {
		expiredBundle := &Bundle{
			BaseCRL: baseCRL,
			Metadata: Metadata{
				CachedAt: time.Now().Add(-DefaultMaxAge - 1*time.Second),
				BaseCRL: CRLMetadata{
					URL: "http://crl",
				},
			}}
		if err := cache.Set(ctx, "expiredKey", expiredBundle); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		_, err = cache.Get(ctx, "expiredKey")
		if !errors.Is(err, ErrCacheMiss) {
			t.Fatalf("expected ErrCacheMiss, got %v", err)
		}
	})

	t.Run("Key doesn't exist", func(t *testing.T) {
		_, err := cache.Get(ctx, "nonExistentKey")
		if !errors.Is(err, ErrCacheMiss) {
			t.Fatalf("expected ErrCacheMiss, got %v", err)
		}
	})

	t.Run("Cache interface", func(t *testing.T) {
		var _ Cache = cache
	})
}

func TestMemoryCacheFailed(t *testing.T) {
	ctx := context.Background()

	// Test Get with invalid type
	t.Run("GetWithInvalidType", func(t *testing.T) {
		cache := NewMemoryCache()
		cache.store.Store("invalidKey", "invalidValue")
		_, err := cache.Get(ctx, "invalidKey")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("ValidateFailed", func(t *testing.T) {
		cache := NewMemoryCache()
		bundle := &Bundle{
			BaseCRL: nil,
			Metadata: Metadata{
				CachedAt: time.Now(),
				BaseCRL: CRLMetadata{
					URL: "http://crl",
				},
			}}
		err := cache.Set(ctx, "invalidBundle", bundle)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}
