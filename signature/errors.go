package signature

import "fmt"

// InvalidSignatureError is used when the signature assocaited is no longer valid.
type InvalidSignatureError struct{}

func (e *InvalidSignatureError) Error() string {
	return "The signature is invalid."
}

// MalformedSignatureError is used when signature envelope is malformed.
type MalformedSignatureError struct{}

func (e *MalformedSignatureError) Error() string {
	return "The signature envelope format is malformed."
}

// UnsupportedSignatureFormatError is used when signature envelope is not supported.
type UnsupportedSignatureFormatError struct {
	sigFormat string
}

func (e *UnsupportedSignatureFormatError) Error() string {
	return fmt.Sprintf("The signature envelope format '%s' is not supported.", e.sigFormat)
}
