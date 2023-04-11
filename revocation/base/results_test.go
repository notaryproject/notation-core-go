package base

import (
	"testing"
)

func TestResultString(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		if OK.String() != "OK" {
			t.Errorf("Expected %s but got %s", "OK", OK.String())
		}
	})
	t.Run("unknown", func(t *testing.T) {
		if Unknown.String() != "Unknown" {
			t.Errorf("Expected %s but got %s", "Unknown", Unknown.String())
		}
	})
	t.Run("revoked", func(t *testing.T) {
		if Revoked.String() != "Revoked" {
			t.Errorf("Expected %s but got %s", "Revoked", Revoked.String())
		}
	})
	t.Run("invalid result", func(t *testing.T) {
		if Result(3).String() != "Invalid Result" {
			t.Errorf("Expected %s but got %s", "Invalid Result", Result(3).String())
		}
	})
}
