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

// Package file provides utilities for file operations.
package file

import "io"

// Using is a helper function to ensure that a resource is closed after using it
// and return the error if any.
func Using[T io.Closer](t T, f func(t T) error) (err error) {
	defer func() {
		if closeErr := t.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	return f(t)
}
