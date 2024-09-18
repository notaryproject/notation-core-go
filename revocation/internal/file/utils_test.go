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

package file

import (
	"errors"
	"testing"
)

func TestUsing(t *testing.T) {
	t.Run("Close error", func(t *testing.T) {
		err := Using(&mockCloser{err: errors.New("closer error")}, func(t *mockCloser) error {
			return nil
		})
		if err.Error() != "closer error" {
			t.Fatalf("expected closer error, got %v", err)
		}
	})

	t.Run("Close without error", func(t *testing.T) {
		err := Using(&mockCloser{}, func(t *mockCloser) error {
			return nil
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}

type mockCloser struct {
	err error
}

func (m *mockCloser) Close() error {
	return m.err
}
