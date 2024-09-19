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

import "errors"

// ErrCacheMiss is an error type for when a cache miss occurs
var ErrCacheMiss = errors.New("cache miss")

// CacheError is an error type for cache errors. The cache error is not a
// critical error, the following operations can be performed normally.
type CacheError struct {
	Err error
}

func (e CacheError) Error() string {
	return e.Err.Error()
}