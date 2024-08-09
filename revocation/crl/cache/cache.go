// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"time"
)

const (
	// DefaultMaxAge is the default maximum age of the CRLs cache.
	// If the CRL is older than DefaultMaxAge, it will be considered as expired.
	DefaultMaxAge = 24 * 7 * time.Hour
)

// Cache is an interface that specifies methods used for caching
type Cache interface {
	// Get retrieves the content with the given key
	//
	// - if the key does not exist, return os.ErrNotExist
	Get(ctx context.Context, key string) (*Bundle, error)

	// Set stores the content with the given key
	//
	// - expiration is the time duration before the content is valid
	Set(ctx context.Context, key string, value *Bundle) error

	// Delete removes the content with the given key
	Delete(ctx context.Context, key string) error

	// Flush removes all content
	Flush(ctx context.Context) error
}
