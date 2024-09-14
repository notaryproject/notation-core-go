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

package result

import (
	"errors"
	"testing"
)

func TestResultString(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		if ResultOK.String() != "OK" {
			t.Errorf("Expected %s but got %s", "OK", ResultOK.String())
		}
	})
	t.Run("non-revokable", func(t *testing.T) {
		if ResultNonRevokable.String() != "NonRevokable" {
			t.Errorf("Expected %s but got %s", "NonRevokable", ResultNonRevokable.String())
		}
	})
	t.Run("unknown", func(t *testing.T) {
		if ResultUnknown.String() != "Unknown" {
			t.Errorf("Expected %s but got %s", "Unknown", ResultUnknown.String())
		}
	})
	t.Run("revoked", func(t *testing.T) {
		if ResultRevoked.String() != "Revoked" {
			t.Errorf("Expected %s but got %s", "Revoked", ResultRevoked.String())
		}
	})
	t.Run("invalid result", func(t *testing.T) {
		if Result(4).String() != "invalid result with value 4" {
			t.Errorf("Expected %s but got %s", "invalid result with value 4", Result(4).String())
		}
	})
}

func TestMethodString(t *testing.T) {
	tests := []struct {
		method   RevocationMethod
		expected string
	}{
		{RevocationMethodOCSP, "OCSP"},
		{RevocationMethodCRL, "CRL"},
		{RevocationMethodOCSPFallbackCRL, "OCSPFallbackCRL"},
		{RevocationMethod(999), "Unknown"}, // Test for default case
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.method.String()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestNewServerResult(t *testing.T) {
	expectedR := &ServerResult{
		Result: ResultNonRevokable,
		Server: "test server",
		Error:  errors.New("test error"),
	}
	r := NewServerResult(expectedR.Result, expectedR.Server, expectedR.Error)
	if r.Result != expectedR.Result {
		t.Errorf("Expected %s but got %s", expectedR.Result, r.Result)
	}
	if r.Server != expectedR.Server {
		t.Errorf("Expected %s but got %s", expectedR.Server, r.Server)
	}
	if r.Error != expectedR.Error {
		t.Errorf("Expected %v but got %v", expectedR.Error, r.Error)
	}
}
