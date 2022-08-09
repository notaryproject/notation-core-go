package signature

import "fmt"

// MalformedSignatureError is used when Signature envelope is malformed.
type MalformedSignatureError struct {
	msg string
}

// NewMalformedSignatureError creates a MalformedSignatureError with the message
func NewMalformedSignatureError(msg string) MalformedSignatureError {
	return MalformedSignatureError{
		msg: msg,
	}
}

// Error returns the error message
func (e MalformedSignatureError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "signature envelope format is malformed"
}

// UnsupportedSigningKeyError is used when a signing key is not supported
type UnsupportedSigningKeyError struct {
	keyType   KeyType
	keyLength int
}

// Error returns the error message
func (e UnsupportedSigningKeyError) Error() string {
	if e.keyType != KeyTypeRSA && e.keyType != KeyTypeEC && e.keyLength != 0 {
		return fmt.Sprintf("%d signing key of size %d is not supported", e.keyType, e.keyLength)
	}
	return "signing key is not supported"
}

// MalformedArgumentError is used when an argument to a function is malformed.
type MalformedArgumentError struct {
	param string
	err   error
}

// Error returns the error message
func (e MalformedArgumentError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%q param is malformed. Error: %s", e.param, e.err.Error())
	}
	return fmt.Sprintf("%q param is malformed", e.param)
}
