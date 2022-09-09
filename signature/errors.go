package signature

import "fmt"

// SignatureIntegrityError is used when the Signature associated is no longer valid.
type SignatureIntegrityError struct {
	err error
}

func (e SignatureIntegrityError) Error() string {
	return fmt.Sprintf("signature is invalid. Error: %s", e.err.Error())
}

// MalformedSignatureError is used when Signature envelope is malformed.
type MalformedSignatureError struct {
	msg string
}

func (e MalformedSignatureError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "signature envelope format is malformed"

}

// UnsupportedSignatureFormatError is used when Signature envelope is not supported.
type UnsupportedSignatureFormatError struct {
	mediaType string
}

func (e UnsupportedSignatureFormatError) Error() string {
	return fmt.Sprintf("signature envelope format with media type %q is not supported", e.mediaType)
}

// SignatureNotFoundError is used when signature envelope is not present.
type SignatureNotFoundError struct{}

func (e SignatureNotFoundError) Error() string {
	return "signature envelope is not present"
}

// SignatureAuthenticityError is used when signature is not generated using trusted certificates.
type SignatureAuthenticityError struct{}

func (e SignatureAuthenticityError) Error() string {
	return "signature is not produced by a trusted signer"
}

// UnsupportedSigningKeyError is used when a signing key is not supported
type UnsupportedSigningKeyError struct {
	keyType   string
	keyLength int
}

func (e UnsupportedSigningKeyError) Error() string {
	if e.keyType != "" && e.keyLength != 0 {
		return fmt.Sprintf("%q signing key of size %d is not supported", e.keyType, e.keyLength)
	}
	return "signing key is not supported"
}

// MalformedArgumentError is used when an argument to a function is malformed.
type MalformedArgumentError struct {
	param string
	err   error
}

func (e MalformedArgumentError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%q param is malformed. Error: %s", e.param, e.err.Error())
	}
	return fmt.Sprintf("%q param is malformed", e.param)
}

// MalformedSignRequestError is used when SignRequest is malformed.
type MalformedSignRequestError struct {
	msg string
}

func (e MalformedSignRequestError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "SignRequest is malformed"
}

// SignatureAlgoNotSupportedError is used when signing algo is not supported.
type SignatureAlgoNotSupportedError struct {
	alg string
}

func (e SignatureAlgoNotSupportedError) Error() string {
	return fmt.Sprintf("signature algorithm %q is not supported", e.alg)
}
