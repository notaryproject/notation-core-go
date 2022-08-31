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
	tests := []struct {
		name   string
		err    *MalformedArgumentError
		expect string
	}{
		{
			name: "err set",
			err: &MalformedArgumentError{
				Param: testParam,
				Err:   errors.New(errMsg),
			},
			expect: fmt.Sprintf("%q param is malformed. Error: %s", testParam, errMsg),
		},
		{
			name:   "err not set",
			err:    &MalformedArgumentError{Param: testParam},
			expect: fmt.Sprintf("%q param is malformed", testParam),
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

func TestMalformedSignRequestError(t *testing.T) {
	tests := []struct {
		name   string
		err    *MalformedSignRequestError
		expect string
	}{
		{
			name:   "err msg set",
			err:    &MalformedSignRequestError{Msg: errMsg},
			expect: errMsg,
		},
		{
			name:   "err msg not set",
			err:    &MalformedSignRequestError{},
			expect: "SignRequest is malformed",
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

func TestSignatureAlgoNotSupportedError(t *testing.T) {
	err := &SignatureAlgoNotSupportedError{
		Alg: testAlg,
	}

	expectMsg := fmt.Sprintf("signature algorithm %q is not supported", testAlg)
	if err.Error() != expectMsg {
		t.Errorf("Expected %s but got %s", expectMsg, err.Error())
	}
}

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

func TestUnsupportedSignatureFormatError(t *testing.T) {
	err := &UnsupportedSignatureFormatError{MediaType: testMediaType}
	expectMsg := fmt.Sprintf("signature envelope format with media type %q is not supported", testMediaType)

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
