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

// fileCache builds on top of OS file system to leverage the file system
// concurrency control and atomicity
type fileCache struct {
	dir string
}

// NewFileCache creates a new file system store
func NewFileCache(dir string, ttl time.Duration) (Cache, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	return &fileCache{dir: dir}, nil
}

func (c *fileCache) Get(ctx context.Context, key string, maxAge time.Duration) (*Bundle, error) {
	f, err := os.Open(filepath.Join(c.dir, key))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	blob, err := ParseBundleFromTarball(f)
	if err != nil {
		return nil, err
	}

	if maxAge != 0 && time.Since(blob.Metadata.BaseCRL.CreateAt) > maxAge {
		return nil, os.ErrNotExist
	}

	return blob, nil
}

func (c *fileCache) Set(ctx context.Context, key string, bundle *Bundle) error {
	tempFile, err := os.CreateTemp("", tempFileName)
	if err != nil {
		return err
	}
	if err := SaveAsTarball(tempFile, bundle); err != nil {
		return err
	}

	tempFile.Close()

	return os.Rename(tempFile.Name(), filepath.Join(c.dir, key))
}

func (c *fileCache) Delete(ctx context.Context, key string) error {
	return os.Remove(filepath.Join(c.dir, key))
}

func (c *fileCache) Clear(ctx context.Context) error {
	return os.RemoveAll(c.dir)
}
