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

package cms

import (
	"errors"
	"testing"
)

func TestSyntaxError(t *testing.T) {
	tests := []struct {
		name    string
		err     SyntaxError
		wantMsg string
	}{
		{"No detail", SyntaxError{Message: "test"}, "cms: syntax error: test"},
		{"With detail", SyntaxError{Message: "test", Detail: errors.New("detail")}, "cms: syntax error: test: detail"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMsg := tt.err.Error(); gotMsg != tt.wantMsg {
				t.Errorf("SyntaxError.Error() = %v, want %v", gotMsg, tt.wantMsg)
			}
			if gotDetail := tt.err.Unwrap(); gotDetail != tt.err.Detail {
				t.Errorf("SyntaxError.Unwrap() = %v, want %v", gotDetail, tt.err.Detail)
			}
		})
	}
}

func TestVerificationError(t *testing.T) {
	tests := []struct {
		name    string
		err     VerificationError
		wantMsg string
	}{
		{"No detail", VerificationError{Message: "test"}, "cms: verification failure: test"},
		{"With detail", VerificationError{Message: "test", Detail: errors.New("detail")}, "cms: verification failure: test: detail"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMsg := tt.err.Error(); gotMsg != tt.wantMsg {
				t.Errorf("VerificationError.Error() = %v, want %v", gotMsg, tt.wantMsg)
			}
			if gotDetail := tt.err.Unwrap(); gotDetail != tt.err.Detail {
				t.Errorf("VerificationError.Unwrap() = %v, want %v", gotDetail, tt.err.Detail)
			}
		})
	}
}
