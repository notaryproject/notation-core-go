package cache

// ParseCRLFromTarballError is an error type for when parsing a CRL from
// a tarball
//
// This error indicates that the tarball was broken or required data was
// missing
type ParseCRLFromTarballError struct {
	Err error
}

func (e *ParseCRLFromTarballError) Error() string {
	return e.Err.Error()
}
