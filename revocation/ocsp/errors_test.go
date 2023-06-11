package ocsp

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRevokedError(t *testing.T) {
	err := &RevokedError{}
	expectedMsg := "certificate is revoked via OCSP"

	if err.Error() != expectedMsg {
		t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
	}
}

func TestUnknownStatusError(t *testing.T) {
	err := &UnknownStatusError{}
	expectedMsg := "certificate has unknown status via OCSP"

	if err.Error() != expectedMsg {
		t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
	}
}

func TestGenericError(t *testing.T) {
	t.Run("without_inner_error", func(t *testing.T) {
		err := &GenericError{}
		expectedMsg := "error checking revocation status via OCSP"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("with_inner_error", func(t *testing.T) {
		err := &GenericError{Err: errors.New("inner error")}
		expectedMsg := "error checking revocation status via OCSP: inner error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})
}

func TestNoServerError(t *testing.T) {
	err := &NoServerError{}
	expectedMsg := "no valid OCSP server found"

	if err.Error() != expectedMsg {
		t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
	}
}

func TestTimeoutError(t *testing.T) {
	duration := 5 * time.Second
	err := &TimeoutError{duration}
	expectedMsg := fmt.Sprintf("exceeded timeout threshold of %.2f seconds for OCSP check", duration.Seconds())

	if err.Error() != expectedMsg {
		t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
	}
}
