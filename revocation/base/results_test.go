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
	t.Run("non-revokable", func(t *testing.T) {
		if NonRevokable.String() != "NonRevokable" {
			t.Errorf("Expected %s but got %s", "NonRevokable", NonRevokable.String())
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
		if Result(4).String() != "invalid result with value 4" {
			t.Errorf("Expected %s but got %s", "invalid result with value 4", Result(4).String())
		}
	})
}
