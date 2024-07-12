package cache

import (
	"io"
)

type Cache interface {
	Get(key string) (io.ReadCloser, error)

	Set(key string) (WriteCanceler, error)

	Delete(key string) error
}

type WriteCanceler interface {
	io.WriteCloser
	Cancel()
}
