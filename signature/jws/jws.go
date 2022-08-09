package jws

import (
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
)

func init() {
	if err := signature.RegisterEnvelopeType(signature.JWSMediaTypeEnvelope, NewEnvelope, ParseEnvelope); err != nil {
		panic(err)
	}
}

type envelope struct {
}

func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{},
	}
}

func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	return &base.Envelope{
		Envelope: &envelope{},
		Raw:      envelopeBytes,
	}, nil
}

func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

func (e *envelope) Payload() (*signature.Payload, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *envelope) SignerInfo() (*signature.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}
