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

	deletedExt           = ".deleted"
	defaultRetryDelay    = 100 * time.Millisecond
	defaultRetryAttempts = 5
)

// FileCache stores in a tarball format, which contains two files: base.crl and
// metadata.json. The base.crl file contains the base CRL in DER format, and the
// metadata.json file contains the metadata of the CRL. The cache builds on top
// of UNIX file system to leverage the file system concurrency control and
// atomicity.
//
// NOTE: For Windows, the atomicity is not guaranteed. Please avoid using this
// cache on Windows when the concurrent write is required.
//
// FileCache doesn't handle cache cleaning but provides the Delete and Clear
// methods to remove the CRLs from the file system.
type FileCache struct {
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
func NewFileCache(opts *FileCacheOptions) (*FileCache, error) {
	if err := os.MkdirAll(opts.Dir, 0700); err != nil {
		return nil, err
	}

	cache := &FileCache{
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
func (c *FileCache) Get(ctx context.Context, key string) (*Bundle, error) {
	f, err := os.Open(filepath.Join(c.dir, key))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bundle, err := ParseBundleFromTarball(f)
	if err != nil {
		return nil, err
	}

	if c.maxAge > 0 && time.Now().After(bundle.Metadata.CreateAt.Add(c.maxAge)) {
		return nil, os.ErrNotExist
	}

	return bundle, nil
}

// Set stores the CRL bundle in the file system
func (c *FileCache) Set(ctx context.Context, key string, bundle *Bundle, expiration time.Duration) error {
	// save to temp file
	tempFile, err := os.CreateTemp("", tempFileName)
	if err != nil {
		return err
	}
	if err := SaveAsTarball(tempFile, bundle); err != nil {
		return err
	}
	tempFile.Close()

	// rename is atomic on UNIX platforms
	return os.Rename(tempFile.Name(), filepath.Join(c.dir, key))
}

// Delete removes the CRL bundle file from file system
func (c *FileCache) Delete(ctx context.Context, key string) error {
	return os.Remove(filepath.Join(c.dir, key))
}

// Clear removes all CRLs from the file system
func (c *FileCache) Clear(ctx context.Context) error {
	return filepath.Walk(c.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		return os.Remove(path)
	})
}
