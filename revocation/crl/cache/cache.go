// Package cache provides methods for caching CRL
//
// The fileSystemCache is an implementation of the Cache interface that uses the
// file system to store CRLs. The file system cache is built on top of the OS
// file system to leverage the file system's concurrency control and atomicity.
//
// The CRL is stored in a tarball format, which contains two files: base.crl and
// metadata.json. The base.crl file contains the base CRL in DER format, and the
// metadata.json file contains the metadata of the CRL.
//
// To implement a new cache, you need to create a new struct that implements the
// Cache interface.
//
// > Note: Please ensure that the implementation supports *CRL as the
// type of value field to cache a CRL.
package cache

import (
	"context"
)

// Cache is an interface that specifies methods used for caching
type Cache interface {
	// Get retrieves the content with the given key
	//
	// - if the key does not exist, return os.ErrNotExist
	Get(ctx context.Context, key string) (*Bundle, error)

	// Set stores the content with the given key
	Set(ctx context.Context, key string, bundle *Bundle) error

	// Delete removes the content with the given key
	Delete(ctx context.Context, key string) error

	// Clear removes all content
	Clear(ctx context.Context) error
}
