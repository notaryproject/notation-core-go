package file

import (
	"errors"
	"testing"
)

func TestUsing(t *testing.T) {
	t.Run("Close error", func(t *testing.T) {
		err := Using(&mockCloser{err: errors.New("closer error")}, func(t *mockCloser) error {
			return nil
		})
		if err.Error() != "closer error" {
			t.Fatalf("expected closer error, got %v", err)
		}
	})

	t.Run("Close without error", func(t *testing.T) {
		err := Using(&mockCloser{}, func(t *mockCloser) error {
			return nil
		})
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}

type mockCloser struct {
	err error
}

func (m *mockCloser) Close() error {
	return m.err
}
