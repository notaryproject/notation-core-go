package signature

import "fmt"

type Envelope interface {
	Sign(req *SignRequest) ([]byte, error)
	Verify() (*Payload, *SignerInfo, error)
	Payload() (*Payload, error)
	SignerInfo() (*SignerInfo, error)
}

type NewEnvelopeFunc func() Envelope
type ParseEnvelopeFunc func([]byte) (Envelope, error)

func RegisterEnvelopeType(mediaType string, newFunc NewEnvelopeFunc, parseFunc ParseEnvelopeFunc) error {
	return nil
}

func NewEnvelope(mediaType string) (Envelope, error) {
	return nil, fmt.Errorf("not implemented")
}

func ParseEnvelope(mediaType string, envelopeBytes []byte) (Envelope, error) {
	return nil, fmt.Errorf("not implemented")
}
