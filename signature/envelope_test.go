package signature

import (
	"reflect"
	"testing"
)

// mock an envelope that implements signature.Envelope.
type testEnvelope struct {
}

// Sign implements Sign of signature.Envelope.
func (e testEnvelope) Sign(req *SignRequest) ([]byte, error) {
	return nil, nil
}

// Verify implements Verify of signature.Envelope.
func (e testEnvelope) Verify() (*Payload, *SignerInfo, error) {
	return nil, nil, nil
}

// Payload implements Payload of signature.Envelope.
func (e testEnvelope) Payload() (*Payload, error) {
	return nil, nil
}

// SignerInfo implements SignerInfo of signature.Envelope.
func (e testEnvelope) SignerInfo() (*SignerInfo, error) {
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
		envelopeFuncs map[string]envelopeFunc
		expect        []string
	}{
		{
			name:          "empty map",
			envelopeFuncs: make(map[string]envelopeFunc),
			expect:        nil,
		},
		{
			name: "nonempty map",
			envelopeFuncs: map[string]envelopeFunc{
				testMediaType: {},
			},
			expect: []string{testMediaType},
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
		envelopeFuncs map[string]envelopeFunc
		expect        Envelope
		expectErr     bool
	}{
		{
			name:          "unsupported media type",
			mediaType:     testMediaType,
			envelopeFuncs: make(map[string]envelopeFunc),
			expect:        nil,
			expectErr:     true,
		},
		{
			name:      "valid media type",
			mediaType: testMediaType,
			envelopeFuncs: map[string]envelopeFunc{
				testMediaType: {
					newFunc: testNewFunc,
				},
			},
			expect:    testEnvelope{},
			expectErr: false,
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
		envelopeFuncs map[string]envelopeFunc
		expect        Envelope
		expectErr     bool
	}{
		{
			name:          "unsupported media type",
			mediaType:     testMediaType,
			envelopeFuncs: make(map[string]envelopeFunc),
			expect:        nil,
			expectErr:     true,
		},
		{
			name:      "valid media type",
			mediaType: testMediaType,
			envelopeFuncs: map[string]envelopeFunc{
				testMediaType: {
					parseFunc: testParseFunc,
				},
			},
			expect:    testEnvelope{},
			expectErr: false,
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
