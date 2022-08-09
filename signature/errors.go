package signature

import "fmt"

// MalformedSignatureError is used when Signature envelope is malformed.
type MalformedSignatureError struct {
	Msg string
}

// Error returns the error message.
func (e *MalformedSignatureError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signature envelope format is malformed"
}

// UnsupportedSigningKeyError is used when a signing key is not supported.
type UnsupportedSigningKeyError struct {
	Msg string
}

// Error returns the error message.
func (e UnsupportedSigningKeyError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "signing key is not supported"
}

// MalformedArgumentError is used when an argument to a function is malformed.
type MalformedArgumentError struct {
	Param string
	Err   error
}

// NewMalformedArgumentError creates a new MalformedArgumentError with malformed
// paramaters and the actual error
func NewMalformedArgumentError(param string, err error) *MalformedArgumentError {
	return &MalformedArgumentError{
		Param: param,
		Err: err,
	}
}

// Error returns the error message.
func (e MalformedArgumentError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%q param is malformed. Error: %s", e.Param, e.Err.Error())
	}
	return fmt.Sprintf("%q param is malformed", e.Param)
}
