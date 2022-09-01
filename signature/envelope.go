// Package signature provides operations for types that implement
// signature.Envelope or signature.Signer.
//
// An Envelope is a structure that creates and verifies a signature using the
// specified signing algorithm with required validation. To register a new
// envelope, call RegisterEnvelopeType first during the initialization.
//
// A Signer is a structure used to sign payload generated after signature
// envelope created. The underlying signing logic is provided by the underlying
// local crypto library or the external signing plugin.
package signature

import "fmt"

// Envelope provides functions to basic functions to manipulate signatures.
type Envelope interface {
	// Sign generates and sign the envelope according to the sign request.
	Sign(req *SignRequest) ([]byte, error)

	// Verify verifies the envelope and returns its enclosed payload and signer
	// info.
	Verify() (*Payload, *SignerInfo, error)

	// Payload returns the payload of the envelope.
	// Payload is trusted only after the successful call to `Verify()`.
	Payload() (*Payload, error)

	// SignerInfo returns the signer information of the envelope.
	// SignerInfo is trusted only after the successful call to `Verify()`.
	SignerInfo() (*SignerInfo, error)
}

// NewEnvelopeFunc defines a function to create a new Envelope.
type NewEnvelopeFunc func() Envelope

// ParseEnvelopeFunc defines a function that takes envelope bytes to create
// an Envelope.
type ParseEnvelopeFunc func([]byte) (Envelope, error)

// envelopeFunc wraps functions to create and parsenew envelopes.
type envelopeFunc struct {
	newFunc   NewEnvelopeFunc
	parseFunc ParseEnvelopeFunc
}

// envelopeFuncs maps envelope media type to corresponding constructors and
// parsers.
var envelopeFuncs map[string]envelopeFunc

// RegisterEnvelopeType registers newFunc and parseFunc for the given mediaType.
// Those functions are intended to be called when creating a new envelope.
// It will be called while inializing the built-in envelopes(JWS/COSE).
func RegisterEnvelopeType(mediaType string, newFunc NewEnvelopeFunc, parseFunc ParseEnvelopeFunc) error {
	if newFunc == nil || parseFunc == nil {
		return fmt.Errorf("required functions not provided")
	}
	if envelopeFuncs == nil {
		envelopeFuncs = make(map[string]envelopeFunc)
	}

	envelopeFuncs[mediaType] = envelopeFunc{
		newFunc:   newFunc,
		parseFunc: parseFunc,
	}
	return nil
}

// RegisteredEnvelopeTypes lists registered envelope media types.
func RegisteredEnvelopeTypes() []string {
	var types []string

	for envelopeType := range envelopeFuncs {
		types = append(types, envelopeType)
	}

	return types
}

// NewEnvelope generates an envelope of given media type.
func NewEnvelope(mediaType string) (Envelope, error) {
	envelopeFunc, ok := envelopeFuncs[mediaType]
	if !ok {
		return nil, &UnsupportedSignatureFormatError{MediaType: mediaType}
	}
	return envelopeFunc.newFunc(), nil
}

// ParseEnvelope generates an envelope by given envelope bytes with specified
// media type.
func ParseEnvelope(mediaType string, envelopeBytes []byte) (Envelope, error) {
	envelopeFunc, ok := envelopeFuncs[mediaType]
	if !ok {
		return nil, &UnsupportedSignatureFormatError{MediaType: mediaType}
	}
	return envelopeFunc.parseFunc(envelopeBytes)
}
