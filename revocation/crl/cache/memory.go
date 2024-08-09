package cache

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// memoryCache is an in-memory cache that stores CRL bundles.
//
// The cache is built on top of the sync.Map to leverage the concurrency control
// and atomicity of the map, so it is suitable for writing once and reading many
// times. The CRL is stored in memory as a Bundle type.
//
// memoryCache doesn't handle cache cleaning but provides the Delete and Clear
// methods to remove the CRLs from the memory.
type memoryCache struct {
	store  sync.Map
	maxAge time.Duration
}

type MemoryCacheOptions struct {
	MaxAge time.Duration
}

// NewMemoryCache creates a new memory store.
//
//   - maxAge is the maximum age of the CRLs cache. If the CRL is older than
//     maxAge, it will be considered as expired.
func NewMemoryCache(opts MemoryCacheOptions) (Cache, error) {
	c := &memoryCache{
		maxAge: opts.MaxAge,
	}

	if c.maxAge == 0 {
		c.maxAge = DefaultMaxAge
	}

	return c, nil
}

// Get retrieves the CRL from the memory store.
func (c *memoryCache) Get(ctx context.Context, key string) (*Bundle, error) {
	value, ok := c.store.Load(key)
	if !ok {
		return nil, os.ErrNotExist
	}

	bundle, ok := value.(*Bundle)
	if !ok {
		return nil, fmt.Errorf("invalid type: %T", value)
	}

	expires := bundle.Metadata.CreateAt.Add(c.maxAge)
	if c.maxAge > 0 && time.Now().After(expires) {
		return nil, &CacheExpiredError{Expires: expires}
	}

	return bundle, nil
}

// Set stores the CRL in the memory store.
func (c *memoryCache) Set(ctx context.Context, key string, bundle *Bundle) error {
	c.store.Store(key, bundle)
	return nil
}

// Delete removes the CRL from the memory store.
func (c *memoryCache) Delete(ctx context.Context, key string) error {
	c.store.Delete(key)
	return nil
}

// Flush removes all CRLs from the memory store.
func (c *memoryCache) Flush(ctx context.Context) error {
	c.store.Range(func(key, value interface{}) bool {
		c.store.Delete(key)
		return true
	})
	return nil
}
