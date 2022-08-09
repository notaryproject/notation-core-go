package signature

import "fmt"

// ErrMalformedSignature is used when Signature envelope is malformed.
type ErrMalformedSignature struct {
	msg string
}

// NewMalformedSignatureError creates a MalformedSignatureError with the message.
func NewErrMalformedSignature(msg string) ErrMalformedSignature {
	return ErrMalformedSignature{
		msg: msg,
	}
}

// Error returns the error message.
func (e ErrMalformedSignature) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "signature envelope format is malformed"
}

// ErrUnsupportedSigningKey is used when a signing key is not supported.
type ErrUnsupportedSigningKey struct {
	keyType   KeyType
	keyLength int
}

// Error returns the error message.
func (e ErrUnsupportedSigningKey) Error() string {
	if e.keyType != KeyTypeRSA && e.keyType != KeyTypeEC && e.keyLength != 0 {
		return fmt.Sprintf("%d signing key of size %d is not supported", e.keyType, e.keyLength)
	}
	return "signing key is not supported"
}

// ErrMalformedArgument is used when an argument to a function is malformed.
type ErrMalformedArgument struct {
	param string
	err   error
}

// Error returns the error message.
func (e ErrMalformedArgument) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%q param is malformed. Error: %s", e.param, e.err.Error())
	}
	return fmt.Sprintf("%q param is malformed", e.param)
}
