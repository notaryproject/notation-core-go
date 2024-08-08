package cache

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// MemoryCache is an in-memory cache that stores CRL bundles.
//
// The cache is built on top of the sync.Map to leverage the concurrency control
// and atomicity of the map, so it is suitable for writing once and reading many
// times. The CRL is stored in memory as a Bundle type.
//
// MemoryCache doesn't handle cache cleaning but provides the Delete and Clear
// methods to remove the CRLs from the memory.
type MemoryCache struct {
	store  sync.Map
	maxAge time.Duration
}

// NewMemoryCache creates a new memory store.
//
//   - maxAge is the maximum age of the CRLs cache. If the CRL is older than
//     maxAge, it will be considered as expired.
func NewMemoryCache(maxAge time.Duration) *MemoryCache {
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}

	return &MemoryCache{
		maxAge: maxAge,
	}
}

// Get retrieves the CRL from the memory store.
func (c *MemoryCache) Get(ctx context.Context, key string) (*Bundle, error) {
	value, ok := c.store.Load(key)
	if !ok {
		return nil, os.ErrNotExist
	}

	bundle, ok := value.(*Bundle)
	if !ok {
		return nil, fmt.Errorf("invalid type: %T", value)
	}

	if c.maxAge > 0 && time.Now().After(bundle.Metadata.CreateAt.Add(c.maxAge)) {
		return nil, os.ErrNotExist
	}

	return bundle, nil
}

// Set stores the CRL in the memory store.
func (c *MemoryCache) Set(ctx context.Context, key string, bundle *Bundle, expiration time.Duration) error {
	c.store.Store(key, bundle)
	return nil
}

// Delete removes the CRL from the memory store.
func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.store.Delete(key)
	return nil
}

// Clear removes all CRLs from the memory store.
func (c *MemoryCache) Clear(ctx context.Context) error {
	c.store.Range(func(key, value interface{}) bool {
		c.store.Delete(key)
		return true
	})
	return nil
}
