package revocation

import (
	"errors"
	"testing"
)

func TestRevokedInOCSPError(t *testing.T) {
	err := &RevokedInOCSPError{}
	expectedMsg := "certificate is revoked via OCSP"

	if err.Error() != expectedMsg {
		t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
	}
}

func TestUnknownInOCSPError(t *testing.T) {
	err := &UnknownInOCSPError{}
	expectedMsg := "certificate has unknown status via OCSP"

	if err.Error() != expectedMsg {
		t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
	}
}

func TestCheckOCSPError(t *testing.T) {
	t.Run("without_inner_error", func(t *testing.T) {
		err := &CheckOCSPError{}
		expectedMsg := "error checking revocation via OCSP"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("with_inner_error", func(t *testing.T) {
		err := &CheckOCSPError{Err: errors.New("inner error")}
		expectedMsg := "error checking revocation via OCSP: inner error"

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

func TestOCSPTimeoutError(t *testing.T) {
	err := &OCSPTimeoutError{}
	expectedMsg := "exceeded timeout threshold for OCSP check"

	if err.Error() != expectedMsg {
		t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
	}
}
