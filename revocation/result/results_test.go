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

func TestCRLReasonCode(t *testing.T) {
	expected := []struct {
		code   int
		reason string
	}{
		{0, "Unspecified"},
		{1, "KeyCompromise"},
		{2, "CACompromise"},
		{3, "AffiliationChanged"},
		{4, "Superseded"},
		{5, "CessationOfOperation"},
		{6, "CertificateHold"},
		{8, "RemoveFromCRL"},
		{9, "PrivilegeWithdrawn"},
		{10, "AACompromise"},
	}

	for _, e := range expected {
		reasonCode := CRLReasonCode(e.code)
		if !reasonCode.Equal(e.code) || reasonCode.String() != e.reason {
			t.Errorf("Expected %s but got %s", e.reason, CRLReasonCode(e.code).String())
		}
	}
}

func TestInvalidCRLReasonCode(t *testing.T) {
	if CRLReasonCode(7).String() != "invalid reason code with value: 7" {
		t.Errorf("Expected %s but got %s", "invalid reason code with value: 7", CRLReasonCode(7).String())
	}

	if CRLReasonCode(11).String() != "invalid reason code with value: 11" {
		t.Errorf("Expected %s but got %s", "invalid reason code with value: 11", CRLReasonCode(11).String())
	}
}
