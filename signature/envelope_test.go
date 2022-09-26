package signature

import (
	"reflect"
	"sync"
	"testing"
)

var (
	emptyFuncs sync.Map
	validFuncs sync.Map
)

func init() {
	validFuncs.Store(testMediaType, envelopeFunc{
		newFunc:   testNewFunc,
		parseFunc: testParseFunc,
	})
}

// mock an envelope that implements signature.Envelope.
type testEnvelope struct {
}

// Sign implements Sign of signature.Envelope.
func (e testEnvelope) Sign(req *SignRequest) ([]byte, error) {
	return nil, nil
}

// Verify implements Verify of signature.Envelope.
func (e testEnvelope) Verify() (*EnvelopeContent, error) {
	return nil, nil
}

// Content implements Content of signature.Envelope.
func (e testEnvelope) Content() (*EnvelopeContent, error) {
	return nil, nil
}

var (
	testNewFunc = func() Envelope {
		return testEnvelope{}
	}
	testParseFunc = func([]byte) (Envelope, error) {
		return testEnvelope{}, nil
	}
)

func TestRegisterEnvelopeType(t *testing.T) {
	tests := []struct {
		name      string
		mediaType string
		newFunc   NewEnvelopeFunc
		parseFunc ParseEnvelopeFunc
		expectErr bool
	}{
		{
			name:      "nil newFunc",
			mediaType: testMediaType,
			newFunc:   nil,
			parseFunc: testParseFunc,
			expectErr: true,
		},
		{
			name:      "nil newParseFunc",
			mediaType: testMediaType,
			newFunc:   testNewFunc,
			parseFunc: nil,
			expectErr: true,
		},
		{
			name:      "valid funcs",
			mediaType: testMediaType,
			newFunc:   testNewFunc,
			parseFunc: testParseFunc,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RegisterEnvelopeType(tt.mediaType, tt.newFunc, tt.parseFunc)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestRegisteredEnvelopeTypes(t *testing.T) {
	tests := []struct {
		name          string
		envelopeFuncs sync.Map
		expect        []string
	}{
		{
			name:          "empty map",
			envelopeFuncs: emptyFuncs,
			expect:        nil,
		},
		{
			name:          "nonempty map",
			envelopeFuncs: validFuncs,
			expect:        []string{testMediaType},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelopeFuncs = tt.envelopeFuncs
			types := RegisteredEnvelopeTypes()

			if !reflect.DeepEqual(types, tt.expect) {
				t.Errorf("got types: %v, expect types: %v", types, tt.expect)
			}
		})
	}
}

func TestNewEnvelope(t *testing.T) {
	tests := []struct {
		name          string
		mediaType     string
		envelopeFuncs sync.Map
		expect        Envelope
		expectErr     bool
	}{
		{
			name:          "unsupported media type",
			mediaType:     testMediaType,
			envelopeFuncs: emptyFuncs,
			expect:        nil,
			expectErr:     true,
		},
		{
			name:          "valid media type",
			mediaType:     testMediaType,
			envelopeFuncs: validFuncs,
			expect:        testEnvelope{},
			expectErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelopeFuncs = tt.envelopeFuncs
			envelope, err := NewEnvelope(tt.mediaType)

			if (err != nil) != tt.expectErr {
				t.Errorf("got error: %v, expected error? %v", err, tt.expectErr)
			}
			if envelope != tt.expect {
				t.Errorf("got envelope: %v, expected envelope? %v", envelope, tt.expect)
			}
		})
	}
}

func TestParseEnvelope(t *testing.T) {
	tests := []struct {
		name          string
		mediaType     string
		envelopeFuncs sync.Map
		expect        Envelope
		expectErr     bool
	}{
		{
			name:          "unsupported media type",
			mediaType:     testMediaType,
			envelopeFuncs: emptyFuncs,
			expect:        nil,
			expectErr:     true,
		},
		{
			name:          "valid media type",
			mediaType:     testMediaType,
			envelopeFuncs: validFuncs,
			expect:        testEnvelope{},
			expectErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelopeFuncs = tt.envelopeFuncs
			envelope, err := ParseEnvelope(tt.mediaType, nil)

			if (err != nil) != tt.expectErr {
				t.Errorf("got error: %v, expected error? %v", err, tt.expectErr)
			}
			if envelope != tt.expect {
				t.Errorf("got envelope: %v, expected envelope? %v", envelope, tt.expect)
			}
		})
	}
}
