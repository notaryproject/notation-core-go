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
	"fmt"
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
	// MaxAge is the maximum age of the CRLs cache. If the CRL is older than
	// MaxAge, it will be considered as expired.
	MaxAge time.Duration

	store sync.Map
}

// NewMemoryCache creates a new memory store.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		MaxAge: DefaultMaxAge,
	}
}

// Get retrieves the CRL from the memory store.
//
// - if the key does not exist, return ErrNotFound
// - if the CRL is expired, return ErrCacheMiss
func (c *MemoryCache) Get(ctx context.Context, uri string) (*Bundle, error) {
	value, ok := c.store.Load(uri)
	if !ok {
		return nil, ErrCacheMiss
	}
	bundle, ok := value.(*Bundle)
	if !ok {
		return nil, fmt.Errorf("invalid type: %T", value)
	}

	expires := bundle.Metadata.CachedAt.Add(c.MaxAge)
	if c.MaxAge > 0 && time.Now().After(expires) {
		return nil, ErrCacheMiss
	}

	return bundle, nil
}

// Set stores the CRL in the memory store.
func (c *MemoryCache) Set(ctx context.Context, uri string, bundle *Bundle) error {
	if err := bundle.Validate(); err != nil {
		return err
	}

	c.store.Store(uri, bundle)
	return nil
}
