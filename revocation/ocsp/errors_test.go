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

func TestOCSPCheckError(t *testing.T) {
	t.Run("without_inner_error", func(t *testing.T) {
		err := &OCSPCheckError{}
		expectedMsg := "error checking revocation status via OCSP"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("with_inner_error", func(t *testing.T) {
		err := &OCSPCheckError{Err: errors.New("inner error")}
		expectedMsg := "error checking revocation status via OCSP: inner error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})
}

func TestNoOCSPServerError(t *testing.T) {
	err := &NoOCSPServerError{}
	expectedMsg := "no valid OCSPServer found"

	if err.Error() != expectedMsg {
		t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
	}
}

func TestPKIXNoCheckError(t *testing.T) {
	err := &PKIXNoCheckError{}
	expectedMsg := fmt.Sprintf("an OCSP signing cert is missing the id-pkix-ocsp-nocheck extension (%s)", pkixNoCheckOID)

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
