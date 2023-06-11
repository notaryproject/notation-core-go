package result

import (
	"errors"
	"testing"
)

func TestInvalidChainError(t *testing.T) {
	t.Run("without_inner_error", func(t *testing.T) {
		err := &InvalidChainError{}
		expectedMsg := "invalid chain: expected chain to be correct and complete"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("inner_error", func(t *testing.T) {
		err := &InvalidChainError{Err: errors.New("inner error")}
		expectedMsg := "invalid chain: expected chain to be correct and complete: inner error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})
}
