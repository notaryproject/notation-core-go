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

func TestInvalidSignatureError(t *testing.T) {
	tests := []struct {
		name   string
		err    *InvalidSignatureError
		expect string
	}{
		{
			name:   "err msg set",
			err:    &InvalidSignatureError{Msg: errMsg},
			expect: errMsg,
		},
		{
			name:   "err msg not set",
			err:    &InvalidSignatureError{},
			expect: "signature envelope format is invalid",
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

func TestInvalidArgumentError(t *testing.T) {
	expectedMsg := "\"hola\" param is invalid"
	validateErrorMsg(&InvalidArgumentError{Param: "hola"}, expectedMsg, t)

	expectedMsg = "\"hola\" param is invalid. Error: se produjo un error"
	validateErrorMsg(&InvalidArgumentError{Param: "hola", Err: fmt.Errorf("se produjo un error")}, expectedMsg, t)
}

func TestUnsupportedSignatureAlgoError(t *testing.T) {
	err := &UnsupportedSignatureAlgoError{
		Alg: testAlg,
	}

	expectMsg := fmt.Sprintf("signature algorithm %q is not supported", testAlg)
	if err.Error() != expectMsg {
		t.Errorf("Expected %s but got %s", expectMsg, err.Error())
	}
}

func TestInvalidSignRequestError(t *testing.T) {
	expectedMsg := "SignRequest is invalid"
	validateErrorMsg(&InvalidSignRequestError{}, expectedMsg, t)

	expectedMsg = "Se produjo un error"
	validateErrorMsg(&InvalidSignRequestError{Msg: expectedMsg}, expectedMsg, t)
}

func validateErrorMsg(err error, expectedMsg string, t *testing.T) {
	foundMsg := err.Error()
	if expectedMsg != foundMsg {
		t.Errorf("Expected %q but found %q", expectedMsg, foundMsg)
	}
}

func TestInvalidArgumentError_Unwrap(t *testing.T) {
	err := &InvalidArgumentError{
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
	err := &DuplicateKeyError{Key: errMsg}
	expectMsg := fmt.Sprintf("repeated key: %q exists.", errMsg)

	if err.Error() != expectMsg {
		t.Errorf("Expected %v but got %v", expectMsg, err.Error())
	}
}
