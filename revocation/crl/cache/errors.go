package cache

import "time"

// CacheExpiredError is an error type that indicates the cache is expired.
type CacheExpiredError struct {
	// Expires is the time when the cache expires.
	Expires time.Time
}

func (e *CacheExpiredError) Error() string {
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
