package cache

import (
	"context"
	"os"
)

// dummyCache is a dummy cache implementation that does nothing
type dummyCache struct {
}

// NewDummyCache creates a new dummy cache
func NewDummyCache() Cache {
	return &dummyCache{}
}

func (c *dummyCache) Get(ctx context.Context, key string) (any, error) {
	return nil, os.ErrNotExist
}

func (c *dummyCache) Set(ctx context.Context, key string, value any) error {
	return nil
}

func (c *dummyCache) Delete(ctx context.Context, key string) error {
	return nil
}

func (c *dummyCache) Clear(ctx context.Context) error {
	return nil
}
