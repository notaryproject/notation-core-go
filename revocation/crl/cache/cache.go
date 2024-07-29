package cache

import (
	"context"
)

// Cache is an interface that specifies methods used for caching
type Cache interface {
	// Get retrieves the content with the given key
	//
	// if the key does not exist, return os.ErrNotExist
	Get(ctx context.Context, key string) (any, error)

	// Set stores the content with the given key
	Set(ctx context.Context, key string, value any) error

	// Delete removes the content with the given key
	Delete(ctx context.Context, key string) error

	// Clear removes all content
	Clear(ctx context.Context) error
}
