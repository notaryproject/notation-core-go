package cache

import (
	"context"
	"os"
	"path/filepath"
	"time"
)

const (
	// tempFileName is the prefix of the temporary file
	tempFileName = "notation-*"
)

// fileCache stores in a tarball format, which contains two files: base.crl and
// metadata.json. The base.crl file contains the base CRL in DER format, and the
// metadata.json file contains the metadata of the CRL. The cache builds on top
// of UNIX file system to leverage the file system concurrency control and
// atomicity.
//
// NOTE: For Windows, the atomicity is not guaranteed. Please avoid using this
// cache on Windows when the concurrent write is required.
//
// fileCache doesn't handle cache cleaning but provides the Delete and Clear
// methods to remove the CRLs from the file system.
type fileCache struct {
	dir    string
	maxAge time.Duration
}

type FileCacheOptions struct {
	Dir    string
	MaxAge time.Duration
}

// NewFileCache creates a new file system store
//
//   - dir is the directory to store the CRLs.
//   - maxAge is the maximum age of the CRLs cache. If the CRL is older than
//     maxAge, it will be considered as expired.
func NewFileCache(opts *FileCacheOptions) (Cache, error) {
	if err := os.MkdirAll(opts.Dir, 0700); err != nil {
		return nil, err
	}

	cache := &fileCache{
		dir:    opts.Dir,
		maxAge: opts.MaxAge,
	}
	if cache.maxAge == 0 {
		cache.maxAge = DefaultMaxAge
	}
	return cache, nil
}

// Get retrieves the CRL bundle from the file system
//
// - if the key does not exist, return os.ErrNotExist
// - if the CRL is expired, return os.ErrNotExist
func (c *fileCache) Get(ctx context.Context, key string) (*Bundle, error) {
	f, err := os.Open(filepath.Join(c.dir, key))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bundle, err := ParseBundleFromTarball(f)
	if err != nil {
		return nil, err
	}

	expires := bundle.Metadata.CreateAt.Add(c.maxAge)
	if c.maxAge > 0 && time.Now().After(expires) {
		// do not delete the file to maintain the idempotent behavior
		return nil, &CacheExpiredError{Expires: expires}
	}

	return bundle, nil
}

// Set stores the CRL bundle in the file system
func (c *fileCache) Set(ctx context.Context, key string, bundle *Bundle) error {
	// save to temp file
	tempFile, err := os.CreateTemp("", tempFileName)
	if err != nil {
		return err
	}
	if err := SaveAsTarball(tempFile, bundle); err != nil {
		return err
	}
	tempFile.Close()

	// rename is atomic on UNIX-like platforms
	return os.Rename(tempFile.Name(), filepath.Join(c.dir, key))
}

// Delete removes the CRL bundle file from file system
func (c *fileCache) Delete(ctx context.Context, key string) error {
	// remove is atomic on UNIX-like platforms
	return os.Remove(filepath.Join(c.dir, key))
}

// Flush removes all CRLs from the file system
func (c *fileCache) Flush(ctx context.Context) error {
	return filepath.Walk(c.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// remove is atomic on UNIX-like platforms
		return os.Remove(path)
	})
}
