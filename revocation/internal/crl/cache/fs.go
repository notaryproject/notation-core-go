package cache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultTTL is the default time to live for the cache
	DefaultTTL = 24 * 7 * time.Hour

	// tempFileName is the prefix of the temporary file
	tempFileName = "notation-*"
)

// fileSystemCache builds on top of OS file system to leverage the file system
// concurrency control and atomicity
type fileSystemCache struct {
	dir string
	ttl time.Duration
}

// NewFileSystemCache creates a new file system store
func NewFileSystemCache(dir string, ttl time.Duration) (Cache, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	if ttl == 0 {
		ttl = DefaultTTL
	}

	return &fileSystemCache{
		dir: dir,
		ttl: ttl,
	}, nil
}

func (c *fileSystemCache) Get(ctx context.Context, key string) (any, error) {
	f, err := os.Open(filepath.Join(c.dir, key))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	blob, err := ParseCRLFromTarball(f)
	if err != nil {
		return nil, err
	}

	if time.Since(blob.Metadata.BaseCRL.CreateAt) > c.ttl {
		return nil, os.ErrNotExist
	}

	return blob, nil
}

func (c *fileSystemCache) Set(ctx context.Context, key string, value any) error {
	var crlBlob *CRL
	switch v := value.(type) {
	case *CRL:
		crlBlob = v
	default:
		return fmt.Errorf("invalid value type: %T", value)
	}

	tempFile, err := os.CreateTemp("", tempFileName)
	if err != nil {
		return err
	}
	if err := SaveAsTarball(tempFile, crlBlob); err != nil {
		return err
	}

	tempFile.Close()

	return os.Rename(tempFile.Name(), filepath.Join(c.dir, key))
}

func (c *fileSystemCache) Delete(ctx context.Context, key string) error {
	return os.Remove(filepath.Join(c.dir, key))
}

func (c *fileSystemCache) Clear(ctx context.Context) error {
	return os.RemoveAll(c.dir)
}