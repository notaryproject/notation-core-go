package base

import (
	"errors"
	"testing"
)

func TestInvalidChainError(t *testing.T) {
	t.Run("nonroot_without_inner_error", func(t *testing.T) {
		err := &InvalidChainError{}
		expectedMsg := "invalid chain: expected chain to be correct and complete"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("nonroot_with_inner_error", func(t *testing.T) {
		err := &InvalidChainError{Err: errors.New("inner error")}
		expectedMsg := "invalid chain: expected chain to be correct and complete: inner error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("root_without_inner_error", func(t *testing.T) {
		err := &InvalidChainError{IsInvalidRoot: true}
		expectedMsg := "invalid chain: expected chain to end with root cert"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("root_with_inner_error", func(t *testing.T) {
		err := &InvalidChainError{Err: errors.New("inner error"), IsInvalidRoot: true}
		expectedMsg := "invalid chain: expected chain to end with root cert: inner error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})
}
