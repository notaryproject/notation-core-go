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

package signature

import (
	"context"
	"fmt"
	"testing"
)

func TestSignRequestContext(t *testing.T) {
	r := &SignRequest{
		ctx: context.WithValue(context.Background(), "k1", "v1"),
	}

	ctx := r.Context()
	if ctx.Value("k1") != "v1" {
		t.Fatal("expected k1:v1 in ctx")
	}

	r = &SignRequest{}
	ctx = r.Context()
	if fmt.Sprint(ctx) != "context.Background" {
		t.Fatal("expected context.Background")
	}
}

func TestSignRequestWithContext(t *testing.T) {
	r := &SignRequest{}
	ctx := context.WithValue(context.Background(), "k1", "v1")
	r = r.WithContext(ctx)
	if r.ctx.Value("k1") != "v1" {
		t.Fatal("expected k1:v1 in request ctx")
	}

	defer func() {
		if rc := recover(); rc == nil {
			t.Errorf("expected to be panic")
		}
	}()
	r.WithContext(nil) // should panic
}
