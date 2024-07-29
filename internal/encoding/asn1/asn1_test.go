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

package asn1

import (
	"fmt"
	"reflect"
	"testing"
)

func TestConvertToDER(t *testing.T) {
	testData := []struct {
		name        string
		ber         []byte
		der         []byte
		expectError bool
	}{
		{
			name: "Constructed value",
			ber: []byte{
				// Constructed value
				0x30,
				// Constructed value length
				0x2e,

				// Type identifier
				0x06,
				// Type length
				0x09,
				// Type content
				0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,

				// Value identifier
				0x04,
				// Value length in BER
				0x81, 0x20,
				// Value content
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
			},
			der: []byte{
				// Constructed value
				0x30,
				// Constructed value length
				0x2d,

				// Type identifier
				0x06,
				// Type length
				0x09,
				// Type content
				0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,

				// Value identifier
				0x04,
				// Value length in BER
				0x20,
				// Value content
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
			},
			expectError: false,
		},
		{
			name: "Primitive value",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0x20,
				// length
				0x81, 0x01,
				// content
				0x01,
			},
			der: []byte{
				// Primitive value
				// identifier
				0x1f, 0x20,
				// length
				0x01,
				// content
				0x01,
			},
			expectError: false,
		},
		{
			name: "Constructed value in constructed value",
			ber: []byte{
				// Constructed value
				0x30,
				// Constructed value length
				0x2d,

				// Constructed value identifier
				0x26,
				// Type length
				0x2b,

				// Value identifier
				0x04,
				// Value length in BER
				0x81, 0x28,
				// Value content
				0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
			},
			der: []byte{
				// Constructed value
				0x30,
				// Constructed value length
				0x2c,

				// Constructed value identifier
				0x26,
				// Type length
				0x2a,

				// Value identifier
				0x04,
				// Value length in BER
				0x28,
				// Value content
				0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
			},
			expectError: false,
		},
		{
			name:        "empty",
			ber:         []byte{},
			der:         []byte{},
			expectError: true,
		},
		{
			name: "identifier high tag number form",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
				// length
				0x81, 0x01,
				// content
				0x01,
			},
			der: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
				// length
				0x01,
				// content
				0x01,
			},
			expectError: false,
		},
		{
			name: "EOF for identifier high tag number form",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0,
			},
			der:         []byte{},
			expectError: true,
		},
		{
			name: "EOF for length",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
			},
			der:         []byte{},
			expectError: true,
		},
		{
			name: "Unsupport indefinite-length",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
				// length
				0x80,
			},
			der:         []byte{},
			expectError: true,
		},
		{
			name: "length greater than 4 bytes",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
				// length
				0x85,
			},
			der:         []byte{},
			expectError: true,
		},
		{
			name: "long form length EOF ",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
				// length
				0x84,
			},
			der:         []byte{},
			expectError: true,
		},
		{
			name: "length greater > int32",
			ber: append([]byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
				// length
				0x84, 0xFF, 0xFF, 0xFF, 0xFF,
			}, make([]byte, 0xFFFFFFFF)...),
			der:         []byte{},
			expectError: true,
		},
		{
			name: "length greater than content",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
				// length
				0x02,
			},
			der:         []byte{},
			expectError: true,
		},
		{
			name: "trailing data",
			ber: []byte{
				// Primitive value
				// identifier
				0x1f, 0xa0, 0x20,
				// length
				0x02,
				// content
				0x01, 0x02, 0x03,
			},
			der:         []byte{},
			expectError: true,
		},
		{
			name: "EOF in constructed value",
			ber: []byte{
				// Constructed value
				0x30,
				// Constructed value length
				0x2c,

				// Constructed value identifier
				0x26,
				// Type length
				0x2b,

				// Value identifier
				0x04,
				// Value length in BER
				0x81, 0x28,
				// Value content
				0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
				0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
				0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8,
			},
			expectError: true,
		},
	}

	for _, tt := range testData {
		der, err := ConvertToDER(tt.ber)
		fmt.Printf("DER: %x\n", der)
		if !tt.expectError && err != nil {
			t.Errorf("ConvertToDER() error = %v, but expect no error", err)
			return
		}
		if tt.expectError && err == nil {
			t.Errorf("ConvertToDER() error = nil, but expect error")
		}

		if !tt.expectError && !reflect.DeepEqual(der, tt.der) {
			t.Errorf("got = %v, want %v", der, tt.der)
		}
	}
}
