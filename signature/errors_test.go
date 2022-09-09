package signature

import (
	"errors"
	"fmt"
	"testing"
)

const (
	errMsg        = "error msg"
	testParam     = "test param"
	testAlg       = "test algorithm"
	testMediaType = "test media type"
)

func TestSignatureIntegrityError(t *testing.T) {
	unwrappedErr := errors.New(errMsg)
	err := &SignatureIntegrityError{
		Err: unwrappedErr,
	}

	expectMsg := fmt.Sprintf("signature is invalid. Error: %s", errMsg)
	if err.Error() != expectMsg {
		t.Errorf("Expected %s but got %s", expectMsg, err.Error())
	}
	if err.Unwrap() != unwrappedErr {
		t.Errorf("Expected %v but got %v", unwrappedErr, err.Unwrap())
	}
}

func TestMalformedSignatureError(t *testing.T) {
	tests := []struct {
		name   string
		err    *MalformedSignatureError
		expect string
	}{
		{
			name:   "err msg set",
			err:    &MalformedSignatureError{Msg: errMsg},
			expect: errMsg,
		},
		{
			name:   "err msg not set",
			err:    &MalformedSignatureError{},
			expect: "signature envelope format is malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if msg != tt.expect {
				t.Errorf("Expected %s but got %s", tt.expect, msg)
			}
		})
	}
}

func TestUnsupportedSignatureFormatError(t *testing.T) {
	err := &UnsupportedSignatureFormatError{MediaType: testMediaType}
	expectMsg := fmt.Sprintf("signature envelope format with media type %q is not supported", testMediaType)

	if err.Error() != expectMsg {
		t.Errorf("Expected %v but got %v", expectMsg, err.Error())
	}
}

func TestUnsupportedSigningKeyError(t *testing.T) {
	tests := []struct {
		name   string
		err    *UnsupportedSigningKeyError
		expect string
	}{
		{
			name:   "err msg set",
			err:    &UnsupportedSigningKeyError{Msg: errMsg},
			expect: errMsg,
		},
		{
			name:   "err msg not set",
			err:    &UnsupportedSigningKeyError{},
			expect: "signing key is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if msg != tt.expect {
				t.Errorf("Expected %s but got %s", tt.expect, msg)
			}
		})
	}
}

func TestMalformedArgumentError(t *testing.T) {
	expectedMsg := "\"hola\" param is malformed"
	validateErrorMsg(&MalformedArgumentError{Param: "hola"}, expectedMsg, t)

	expectedMsg = "\"hola\" param is malformed. Error: se produjo un error"
	validateErrorMsg(&MalformedArgumentError{Param: "hola", Err: fmt.Errorf("se produjo un error")}, expectedMsg, t)
}

func TestSignatureAlgoNotSupportedError(t *testing.T) {
	err := &SignatureAlgoNotSupportedError{
		Alg: testAlg,
	}

	expectMsg := fmt.Sprintf("signature algorithm %q is not supported", testAlg)
	if err.Error() != expectMsg {
		t.Errorf("Expected %s but got %s", expectMsg, err.Error())
	}
}

func TestMalformedSignRequestError(t *testing.T) {
	expectedMsg := "SignRequest is malformed"
	validateErrorMsg(&MalformedSignRequestError{}, expectedMsg, t)

	expectedMsg = "Se produjo un error"
	validateErrorMsg(&MalformedSignRequestError{Msg: expectedMsg}, expectedMsg, t)
}

func validateErrorMsg(err error, expectedMsg string, t *testing.T) {
	foundMsg := err.Error()
	if expectedMsg != foundMsg {
		t.Errorf("Expected %q but found %q", expectedMsg, foundMsg)
	}
}

func TestMalformedArgumentError_Unwrap(t *testing.T) {
	err := &MalformedArgumentError{
		Param: testParam,
		Err:   errors.New(errMsg),
	}
	unwrappedErr := err.Unwrap()
	if unwrappedErr.Error() != errMsg {
		t.Errorf("Expected %s but got %s", errMsg, unwrappedErr.Error())
	}
}

func TestSignatureEnvelopeNotFoundError(t *testing.T) {
	err := &SignatureEnvelopeNotFoundError{}
	expectMsg := "signature envelope is not present"

	if err.Error() != expectMsg {
		t.Errorf("Expected %v but got %v", expectMsg, err.Error())
	}
}

func TestSignatureAuthenticityError(t *testing.T) {
	err := &SignatureAuthenticityError{}
	expectMsg := "signature is not produced by a trusted signer"

	if err.Error() != expectMsg {
		t.Errorf("Expected %v but got %v", expectMsg, err.Error())
	}
}

func TestEnvelopeKeyRepeatedError(t *testing.T) {
	err := &EnvelopeKeyRepeatedError{Key: errMsg}
	expectMsg := fmt.Sprintf("repeated key: %q exists in the envelope.", errMsg)

	if err.Error() != expectMsg {
		t.Errorf("Expected %v but got %v", expectMsg, err.Error())
	}
}
