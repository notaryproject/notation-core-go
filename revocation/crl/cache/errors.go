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

package cache

import "errors"

// BrokenFileError is an error type for when parsing a CRL from
// a tarball
//
// This error indicates that the tarball was broken or required data was
// missing
type BrokenFileError struct {
	Err error
}

func (e *BrokenFileError) Error() string {
	return e.Err.Error()
}

// ErrCacheMiss is an error type for when a cache miss occurs
var ErrCacheMiss = errors.New("cache miss")
