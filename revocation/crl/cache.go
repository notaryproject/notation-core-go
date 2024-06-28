package crl

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
)

type Cache interface {
	// Get retrieves the CRL from the store
	Get(key string) ([]byte, error)

	// Set stores the CRL in the store
	Set(key string, value []byte) error
}

type fileSystemCache struct {
	dir string

	// mu protects the cache
	mu sync.RWMutex
}

// NewFileSystemCache creates a new file system store
func NewFileSystemCache(dir string) Cache {
	return &fileSystemCache{
		dir: dir,
		mu:  sync.RWMutex{},
	}
}

func (f *fileSystemCache) Get(key string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	fileName := hashURL(key)
	return os.ReadFile(filepath.Join(f.dir, fileName))
}

// Set stores the CRL in the store. It hashes the URL to determine the
// filename to store the CRL in.
func (f *fileSystemCache) Set(key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	fileName := hashURL(key)
	return os.WriteFile(filepath.Join(f.dir, fileName), value, 0644)
}

type memeoryCache struct {
	cache map[string][]byte

	// mu protects the cache
	mu sync.RWMutex
}

// NewMemoryCache creates a new memory store
func NewMemoryCache() Cache {
	return &memeoryCache{
		cache: make(map[string][]byte),
		mu:    sync.RWMutex{},
	}
}

func (m *memeoryCache) Get(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cache[key], nil
}

func (m *memeoryCache) Set(key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[key] = value
	return nil
}

// hashURL hashes the URL with SHA256 and returns the hex-encoded result
func hashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}
