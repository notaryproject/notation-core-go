package signature

import (
	"fmt"
)

// MalformedSignatureError is used when Signature envelope is malformed.
type MalformedSignatureError struct {
	Msg string
}

// Error returns the error message or the default message if not provided.
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

// Error returns the error message or the default message if not provided.
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

// Error returns the error message or the default message if not provided.
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

// Error returns the formatted error message.
func (e *SignatureAlgoNotSupportedError) Error() string {
	return fmt.Sprintf("signature algorithm %q is not supported", e.Alg)
}

// SignatureIntegrityError is used when the signature associated is no longer
// valid.
type SignatureIntegrityError struct {
	Err error
}

// Error returns the formatted error message.
func (e *SignatureIntegrityError) Error() string {
	return fmt.Sprintf("signature is invalid. Error: %s", e.Err.Error())
}

// Unwrap unwraps the internal error.
func (e *SignatureIntegrityError) Unwrap() error {
	return e.Err
}

// SignatureNotFoundError is used when signature envelope is not present.
type SignatureNotFoundError struct{}

// Error returns the default error message.
func (e *SignatureNotFoundError) Error() string {
	return "signature envelope is not present"
}

// SignatureAuthenticityError is used when signature is not generated using
// trusted certificates.
type SignatureAuthenticityError struct{}

// Error returns the default error message.
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

// Error returns the formatted error message.
func (e *EnvelopeKeyRepeatedError) Error() string {
	return fmt.Sprintf(`repeated key: "%s" exists in the both protected header and extended signed attributes.`, e.Key)
}

// RemoteSigningError is used when remote signer causes the error.
type RemoteSigningError struct {
	Msg string
}

// Error returns formated remote signing error
func (e *RemoteSigningError) Error() string {
	return fmt.Sprintf("remote signing error. Error: %s", e.Msg)
}
