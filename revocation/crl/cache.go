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

package crl

import "context"

// Cache is an interface that specifies methods used for caching
type Cache interface {
	// Get retrieves the CRL bundle with the given url
	//
	// url is the key to retrieve the CRL bundle
	//
	// if the key does not exist or the content is expired, return ErrCacheMiss.
	Get(ctx context.Context, url string) (*Bundle, error)

	// Set stores the CRL bundle with the given url
	//
	// url is the key to store the CRL bundle
	// bundle is the CRL collections to store
	Set(ctx context.Context, url string, bundle *Bundle) error
}
