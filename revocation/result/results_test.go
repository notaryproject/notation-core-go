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
