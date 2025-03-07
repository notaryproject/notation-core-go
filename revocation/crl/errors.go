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

// ErrCacheMiss is returned when a cache miss occurs.
var ErrCacheMiss = errors.New("cache miss")

// errDeltaCRLNotFound is returned when a delta CRL is not found.
var errDeltaCRLNotFound = errors.New("delta CRL not found")
