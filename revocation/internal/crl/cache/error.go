package cache

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
