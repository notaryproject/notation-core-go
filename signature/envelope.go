// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

import (
	"fmt"
	"sync"
)

// Envelope provides basic functions to manipulate signatures.
type Envelope interface {
	// Sign generates and sign the envelope according to the sign request.
	Sign(req *SignRequest) ([]byte, error)

	// Verify verifies the envelope and returns its enclosed payload and signer
	// info.
	Verify() (*EnvelopeContent, error)

	// Content returns the payload and signer information of the envelope.
	// Content is trusted only after the successful call to `Verify()`.
	Content() (*EnvelopeContent, error)
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
var envelopeFuncs sync.Map // map[string]envelopeFunc

// RegisterEnvelopeType registers newFunc and parseFunc for the given mediaType.
// Those functions are intended to be called when creating a new envelope.
// It will be called while inializing the built-in envelopes(JWS/COSE).
func RegisterEnvelopeType(mediaType string, newFunc NewEnvelopeFunc, parseFunc ParseEnvelopeFunc) error {
	if newFunc == nil || parseFunc == nil {
		return fmt.Errorf("required functions not provided")
	}
	envelopeFuncs.Store(mediaType, envelopeFunc{
		newFunc:   newFunc,
		parseFunc: parseFunc,
	})
	return nil
}

// RegisteredEnvelopeTypes lists registered envelope media types.
func RegisteredEnvelopeTypes() []string {
	var types []string

	envelopeFuncs.Range(func(k, v any) bool {
		types = append(types, k.(string))
		return true
	})

	return types
}

// NewEnvelope generates an envelope of given media type.
func NewEnvelope(mediaType string) (Envelope, error) {
	val, ok := envelopeFuncs.Load(mediaType)
	if !ok {
		return nil, &UnsupportedSignatureFormatError{MediaType: mediaType}
	}
	return val.(envelopeFunc).newFunc(), nil
}

// ParseEnvelope generates an envelope for given envelope bytes with specified
// media type.
func ParseEnvelope(mediaType string, envelopeBytes []byte) (Envelope, error) {
	val, ok := envelopeFuncs.Load(mediaType)
	if !ok {
		return nil, &UnsupportedSignatureFormatError{MediaType: mediaType}
	}
	return val.(envelopeFunc).parseFunc(envelopeBytes)
}
