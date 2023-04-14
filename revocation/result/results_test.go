package result

import (
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
		if Result(0).String() != "invalid result with value 0" {
			t.Errorf("Expected %s but got %s", "invalid result with value 0", Result(0).String())
		}
		if Result(5).String() != "invalid result with value 5" {
			t.Errorf("Expected %s but got %s", "invalid result with value 5", Result(5).String())
		}
	})
}
