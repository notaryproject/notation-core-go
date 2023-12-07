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

// Package asn1 decodes BER-encoded ASN.1 data structures and encodes in DER.
// Note:
// - DER is a subset of BER.
// - Indefinite length is not supported.
// - The length of the encoded data must fit the memory space of the int type (4 bytes).
//
// Reference:
// - http://luca.ntop.org/Teaching/Appunti/asn1.html
// - ISO/IEC 8825-1
package asn1

import (
	"bytes"
	"encoding/asn1"
)

// Common errors
var (
	ErrEarlyEOF                    = asn1.SyntaxError{Msg: "early EOF"}
	ErrTrailingData                = asn1.SyntaxError{Msg: "trailing data"}
	ErrUnsupportedLength           = asn1.StructuralError{Msg: "length method not supported"}
	ErrUnsupportedIndefiniteLength = asn1.StructuralError{Msg: "indefinite length not supported"}
)

// value represents an ASN.1 value.
type value interface {
	// EncodeMetadata encodes the identifier and length in DER to the buffer.
	EncodeMetadata(*bytes.Buffer) error

	// EncodedLen returns the length in bytes of the encoded data.
	EncodedLen() int

	// Content returns the content of the value.
	// For primitive values, it returns the content octets.
	// For constructed values, it returns nil because the content is
	// the data of all members.
	Content() []byte
}

// ConvertToDER converts BER-encoded ASN.1 data structures to DER-encoded.
func ConvertToDER(ber []byte) ([]byte, error) {
	flatValues, err := decode(ber)
	if err != nil {
		return nil, err
	}

	// get the total length from the root value and allocate a buffer
	buf := bytes.NewBuffer(make([]byte, 0, flatValues[0].EncodedLen()))
	for _, v := range flatValues {
		if err = v.EncodeMetadata(buf); err != nil {
			return nil, err
		}

		if content := v.Content(); content != nil {
			// primitive value
			_, err = buf.Write(content)
			if err != nil {
				return nil, err
			}
		}
	}

	return buf.Bytes(), nil
}

// decode decodes BER-encoded ASN.1 data structures.
// To get the DER of `r`, encode the values
// in the returned slice in order.
//
// Parameters:
// r - The input byte slice.
//
// Return:
// []value - The returned value, which is the flat slice of ASN.1 values,
// contains the nodes from a depth-first traversal.
// error - An error that can occur during the decoding process.
//
// Reference: ISO/IEC 8825-1: 8.1.1.3
func decode(r []byte) ([]value, error) {
	// prepare the first value
	identifier, content, r, err := decodeMetadata(r)
	if err != nil {
		return nil, err
	}
	if len(r) != 0 {
		return nil, ErrTrailingData
	}

	// primitive value
	if isPrimitive(identifier) {
		return []value{&primitiveValue{
			identifier: identifier,
			content:    content,
		}}, nil
	}

	// constructed value
	rootConstructed := &constructedValue{
		identifier: identifier,
		rawContent: content,
	}
	flatValues := []value{rootConstructed}

	// start depth-first decoding with stack
	valueStack := []*constructedValue{rootConstructed}
	for len(valueStack) > 0 {
		stackLen := len(valueStack)
		// top
		node := valueStack[stackLen-1]

		// check that the constructed value is fully decoded
		if len(node.rawContent) == 0 {
			// calculate the length of the members
			for _, m := range node.members {
				node.length += m.EncodedLen()
			}
			// pop
			valueStack = valueStack[:stackLen-1]
			continue
		}

		// decode the next member of the constructed value
		identifier, content, node.rawContent, err = decodeMetadata(node.rawContent)
		if err != nil {
			return nil, err
		}
		if isPrimitive(identifier) {
			// primitive value
			primitiveNode := &primitiveValue{
				identifier: identifier,
				content:    content,
			}
			node.members = append(node.members, primitiveNode)
			flatValues = append(flatValues, primitiveNode)
		} else {
			// constructed value
			constructedNode := &constructedValue{
				identifier: identifier,
				rawContent: content,
			}
			node.members = append(node.members, constructedNode)

			// add a new constructed node to the stack
			valueStack = append(valueStack, constructedNode)
			flatValues = append(flatValues, constructedNode)
		}
	}
	return flatValues, nil
}

// decodeMetadata decodes the metadata of a BER-encoded ASN.1 value.
//
// Parameters:
// r - The input byte slice.
//
// Return:
// []byte - The identifier octets.
// []byte - The content octets.
// []byte - The subsequent octets after the value.
// error - An error that can occur during the decoding process.
//
// Reference: ISO/IEC 8825-1: 8.1.1.3
func decodeMetadata(r []byte) ([]byte, []byte, []byte, error) {
	// structure of an encoding (primitive or constructed)
	// +----------------+----------------+----------------+
	// | identifier     | length         | content        |
	// +----------------+----------------+----------------+
	identifier, r, err := decodeIdentifier(r)
	if err != nil {
		return nil, nil, nil, err
	}
	contentLen, r, err := decodeLength(r)
	if err != nil {
		return nil, nil, nil, err
	}

	if contentLen > len(r) {
		return nil, nil, nil, ErrEarlyEOF
	}
	return identifier, r[:contentLen], r[contentLen:], nil
}

// decodeIdentifier decodes decodeIdentifier octets.
//
// Parameters:
// r - The input byte slice from which the identifier octets are to be decoded.
//
// Returns:
// []byte - The identifier octets decoded from the input byte slice.
// []byte - The remaining part of the input byte slice after the identifier octets.
// error - An error that can occur during the decoding process.
//
// Reference: ISO/IEC 8825-1: 8.1.2
func decodeIdentifier(r []byte) ([]byte, []byte, error) {
	if len(r) < 1 {
		return nil, nil, ErrEarlyEOF
	}
	offset := 0
	b := r[offset]
	offset++

	// high-tag-number form
	// Reference: ISO/IEC 8825-1: 8.1.2.4
	if b&0x1f == 0x1f {
		for offset < len(r) && r[offset]&0x80 == 0x80 {
			offset++
		}
		if offset >= len(r) {
			return nil, nil, ErrEarlyEOF
		}
		offset++
	}
	return r[:offset], r[offset:], nil
}

// decodeLength decodes length octets.
// Indefinite length is not supported
//
// Parameters:
// r - The input byte slice from which the length octets are to be decoded.
//
// Returns:
// int - The length decoded from the input byte slice.
// []byte - The remaining part of the input byte slice after the length octets.
// error - An error that can occur during the decoding process.
//
// Reference: ISO/IEC 8825-1: 8.1.3
func decodeLength(r []byte) (int, []byte, error) {
	if len(r) < 1 {
		return 0, nil, ErrEarlyEOF
	}
	offset := 0
	b := r[offset]
	offset++

	if b < 0x80 {
		// short form
		// Reference: ISO/IEC 8825-1: 8.1.3.4
		return int(b), r[offset:], nil
	} else if b == 0x80 {
		// Indefinite-length method is not supported.
		// Reference: ISO/IEC 8825-1: 8.1.3.6.1
		return 0, nil, ErrUnsupportedIndefiniteLength
	}

	// long form
	// Reference: ISO/IEC 8825-1: 8.1.3.5
	n := int(b & 0x7f)
	if n > 4 {
		// length must fit the memory space of the int type (4 bytes).
		return 0, nil, ErrUnsupportedLength
	}
	if offset+n >= len(r) {
		return 0, nil, ErrEarlyEOF
	}
	var length uint64
	for i := 0; i < n; i++ {
		length = (length << 8) | uint64(r[offset])
		offset++
	}

	// length must fit the memory space of the int32.
	if (length >> 31) > 0 {
		return 0, nil, ErrUnsupportedLength
	}
	return int(length), r[offset:], nil
}

// isPrimitive returns true if the first identifier octet is marked
// as primitive.
// Reference: ISO/IEC 8825-1: 8.1.2.5
func isPrimitive(identifier []byte) bool {
	return identifier[0]&0x20 == 0
}
