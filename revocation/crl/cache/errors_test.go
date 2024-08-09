package cache

import (
	"errors"
	"testing"
	"time"
)

func TestCacheExpiredError(t *testing.T) {
	expirationTime := time.Now()
	err := &CacheExpiredError{Expires: expirationTime}

	expectedMessage := "cache expired at " + expirationTime.String()
	if err.Error() != expectedMessage {
		t.Errorf("expected %q, got %q", expectedMessage, err.Error())
	}
}

func TestBrokenFileError(t *testing.T) {
	innerErr := errors.New("inner error")
	err := &BrokenFileError{Err: innerErr}

	if err.Error() != innerErr.Error() {
		t.Errorf("expected %q, got %q", innerErr.Error(), err.Error())
	}
}
