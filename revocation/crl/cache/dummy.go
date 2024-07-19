package cache

import (
	"io"
	"os"
)

// dummyCache is a dummy cache implementation that does nothing
type dummyCache struct {
}

// NewDummyCache creates a new dummy cache
func NewDummyCache() Cache {
	return &dummyCache{}
}

// Get always returns os.ErrNotExist
func (d *dummyCache) Get(fileName string) (io.ReadCloser, error) {
	return nil, os.ErrNotExist
}

// Set returns a dummyWriter
func (d *dummyCache) Set(filename string) (WriteCanceler, error) {
	return &dummyWriter{}, nil
}

// List returns empty list
func (d *dummyCache) List() ([]string, error) {
	return nil, nil
}

// Delete does nothing
func (d *dummyCache) Delete(fileName string) error {
	return nil
}

// dummyWriter is a dummy writer implementation that does nothing
type dummyWriter struct {
}

// Write does nothing
func (d *dummyWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// Cancel does nothing
func (d *dummyWriter) Cancel() {
}

// Close does nothing
func (d *dummyWriter) Close() error {
	return nil
}
