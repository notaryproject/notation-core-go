package signature

import (
	"fmt"
)

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
func (e *UnsupportedSigningKeyError) Error() string {
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

// Error returns the error message.
func (e *MalformedArgumentError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%q param is malformed. Error: %s", e.Param, e.Err.Error())
	}
	return fmt.Sprintf("%q param is malformed", e.Param)
}

// Unwrap returns the unwrapped error
func (e *MalformedArgumentError) Unwrap() error {
	return e.Err
}

// MalformedSignRequestError is used when SignRequest is malformed.
type MalformedSignRequestError struct {
	Msg string
}

func (e *MalformedSignRequestError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "SignRequest is malformed"
}

// SignatureAlgoNotSupportedError is used when signing algo is not supported.
type SignatureAlgoNotSupportedError struct {
	Alg string
}

func (e *SignatureAlgoNotSupportedError) Error() string {
	return fmt.Sprintf("signature algorithm %q is not supported", e.Alg)
}

// SignatureIntegrityError is used when the Signature associated is no longer valid.
type SignatureIntegrityError struct {
	Err error
}

func (e *SignatureIntegrityError) Error() string {
	return fmt.Sprintf("signature is invalid. Error: %s", e.Err.Error())
}

func (e *SignatureIntegrityError) Unwrap() error {
	return e.Err
}

// SignatureNotFoundError is used when signature envelope is not present.
type SignatureNotFoundError struct{}

func (e *SignatureNotFoundError) Error() string {
	return "signature envelope is not present"
}

// SignatureAuthenticityError is used when signature is not generated using
// trusted certificates.
type SignatureAuthenticityError struct{}

func (e *SignatureAuthenticityError) Error() string {
	return "signature is not produced by a trusted signer"
}

// UnsupportedSignatureFormatError is used when Signature envelope is not supported.
type UnsupportedSignatureFormatError struct {
	MediaType string
}

// Error returns the formatted error message.
func (e *UnsupportedSignatureFormatError) Error() string {
	return fmt.Sprintf("signature envelope format with media type %q is not supported", e.MediaType)
}

// EnvelopeKeyRepeatedError is used when repeated key name found in the envelope.
type EnvelopeKeyRepeatedError struct {
	Key string
}

// Error returns the formatted error message
func (e *EnvelopeKeyRepeatedError) Error() string {
	return fmt.Sprintf("repeated key: `%s` exists in the envelope.", e.Key)
}
