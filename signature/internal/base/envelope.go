package base

import (
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
)

type Envelope struct {
	signature.Envelope
	Raw []byte
}

func (e *Envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	err := validateSignRequest(req)
	if err != nil {
		return nil, err
	}
	e.Raw, err = e.Envelope.Sign(req)
	if err != nil {
		return nil, err
	}
	return e.Raw, nil
}

func (e *Envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

func (e *Envelope) Payload() (*signature.Payload, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *Envelope) SignerInfo() (*signature.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

// validateSignRequest performs basic set of validations on SignRequest struct.
func validateSignRequest(req *signature.SignRequest) error {
	return nil
}
