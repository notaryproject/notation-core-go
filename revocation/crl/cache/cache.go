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
	// Get retrieves the CRL bundle with the given uri
	//
	// uri is the URI of the CRL
	//
	// - if the key does not exist, return NotExistError
	// - if the content is expired, return ExpiredError
	Get(ctx context.Context, uri string) (*Bundle, error)

	// Set stores the CRL bundle with the given uri
	Set(ctx context.Context, uri string, bundle *Bundle) error

	// Delete removes the CRL bundle with the given uri
	Delete(ctx context.Context, uri string) error

	// Flush removes all content
	Flush(ctx context.Context) error
}
