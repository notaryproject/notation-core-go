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

package ber

import (
	"io"
)

// Writer is the interface that wraps the basic Write and WriteByte methods.
type Writer interface {
	io.Writer
	io.ByteWriter
}

// encodeLength encodes length octets in DER.
// Reference: ISO/IEC 8825-1: 10.1
func encodeLength(w io.ByteWriter, length int) error {
	// DER restriction: short form must be used for length less than 128
	if length < 0x80 {
		return w.WriteByte(byte(length))
	}

	// DER restriction: long form must be encoded in the minimum number of octets
	lengthSize := encodedLengthSize(length)
	err := w.WriteByte(0x80 | byte(lengthSize-1))
	if err != nil {
		return err
	}
	for i := lengthSize - 1; i > 0; i-- {
		if err = w.WriteByte(byte(length >> (8 * (i - 1)))); err != nil {
			return err
		}
	}
	return nil
}

// encodedLengthSize gives the number of octets used for encoding the length
// in DER.
// Reference: ISO/IEC 8825-1: 10.1
func encodedLengthSize(length int) int {
	if length < 0x80 {
		return 1
	}

	lengthSize := 1
	for ; length > 0; lengthSize++ {
		length >>= 8
	}
	return lengthSize
}
