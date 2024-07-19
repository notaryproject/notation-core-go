package cache

import (
	"io"
)

// Cache is an interface to store the content
type Cache interface {
	// Get retrieves the content with the given key
	//
	// if the key does not exist, return os.ErrNotExist
	Get(key string) (io.ReadCloser, error)

	// Set stores the content with the given key
	Set(key string) (WriteCanceler, error)

	// List returns the list of keys
	List() ([]string, error)

	// Delete removes the content with the given key
	Delete(key string) error
}

type WriteCanceler interface {
	io.WriteCloser
	Cancel()
}
