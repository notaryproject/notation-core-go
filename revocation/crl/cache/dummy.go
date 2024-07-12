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

// Get retrieves the CRL from the store
func (d *dummyCache) Get(fileName string) (io.ReadCloser, error) {
	return nil, os.ErrNotExist
}

// Set stores the CRL in the store
func (d *dummyCache) Set(filename string) (WriteCanceler, error) {
	return &dummyWriter{}, nil
}

func (d *dummyCache) Delete(fileName string) error {
	return nil
}

// dummyWriter is a WriteCanceler implementation that writes to
// a bytes.Buffer
type dummyWriter struct {
}

func (d *dummyWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (d *dummyWriter) Cancel() {
}

func (d *dummyWriter) Close() error {
	return nil
}
