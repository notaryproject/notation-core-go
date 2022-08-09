package signer

import (
	"fmt"
	"testing"
)

func TestSignatureIntegrityError(t *testing.T) {
	expectedMsg := "signature is invalid. Error: se produjo un error"
	validateErrorMsg(SignatureIntegrityError{err: fmt.Errorf("se produjo un error")}, expectedMsg, t)
}

func TestMalformedSignatureError(t *testing.T) {
	expectedMsg := "signature envelope format is malformed"
	validateErrorMsg(MalformedSignatureError{}, expectedMsg, t)

	expectedMsg = "Se produjo un error"
	validateErrorMsg(MalformedSignatureError{msg: expectedMsg}, expectedMsg, t)
}

func TestUnsupportedSignatureFormatError(t *testing.T) {
	expectedMsg := "signature envelope format with media type \"hola\" is not supported"
	validateErrorMsg(UnsupportedSignatureFormatError{mediaType: "hola"}, expectedMsg, t)
}

func TestUnsupportedSigningKeyError(t *testing.T) {
	expectedMsg := "signing key is not supported"
	validateErrorMsg(UnsupportedSigningKeyError{}, expectedMsg, t)
	validateErrorMsg(UnsupportedSigningKeyError{keyType: "RSA"}, expectedMsg, t)
	validateErrorMsg(UnsupportedSigningKeyError{keyLength: 1024}, expectedMsg, t)

	expectedMsg = "\"RSA\" signing key of size 1024 is not supported"
	validateErrorMsg(UnsupportedSigningKeyError{keyType: "RSA", keyLength: 1024}, expectedMsg, t)
}

func TestMalformedArgumentError(t *testing.T) {
	expectedMsg := "\"hola\" param is malformed"
	validateErrorMsg(MalformedArgumentError{param: "hola"}, expectedMsg, t)

	expectedMsg = "\"hola\" param is malformed. Error: se produjo un error"
	validateErrorMsg(MalformedArgumentError{param: "hola", err: fmt.Errorf("se produjo un error")}, expectedMsg, t)
}

func TestSignatureAlgoNotSupportedError(t *testing.T) {
	expectedMsg := "signature algorithm \"hola\" is not supported"
	validateErrorMsg(SignatureAlgoNotSupportedError{alg: "hola"}, expectedMsg, t)
}

func TestMalformedSignRequestError(t *testing.T) {
	expectedMsg := "SignRequest is malformed"
	validateErrorMsg(MalformedSignRequestError{}, expectedMsg, t)

	expectedMsg = "Se produjo un error"
	validateErrorMsg(MalformedSignRequestError{msg: expectedMsg}, expectedMsg, t)
}

func validateErrorMsg(err error, expectedMsg string, t *testing.T) {
	foundMsg := err.Error()
	if expectedMsg != foundMsg {
		t.Errorf("Expected %q but found %q", expectedMsg, foundMsg)
	}
}
