package cache

import "time"

// NotExistError is an error type that indicates the key is not found in the
// cache.
type NotExistError struct {
	Key string
}

func (e *NotExistError) Error() string {
	return "key not found: " + e.Key
}

// ExpiredError is an error type that indicates the cache is expired.
type ExpiredError struct {
	// Expires is the time when the cache expires.
	Expires time.Time
}

func (e *ExpiredError) Error() string {
	return "cache expired at " + e.Expires.String()
}

// BrokenFileError is an error type for when parsing a CRL from
// a tarball
//
// This error indicates that the tarball was broken or required data was
// missing
type BrokenFileError struct {
	Err error
}

func (e *BrokenFileError) Error() string {
	return e.Err.Error()
}
