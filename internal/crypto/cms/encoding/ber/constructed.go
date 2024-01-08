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

// constructed represents a value in constructed.
type constructed struct {
	identifier []byte
	length     int // length of this constructed value's memebers in bytes when encoded in DER
	members    []value
	rawContent []byte // the raw content of BER
}

// EncodeMetadata encodes the identifier and length octets of constructed
// to the value writer in DER.
func (v *constructed) EncodeMetadata(w Writer) error {
	_, err := w.Write(v.identifier)
	if err != nil {
		return err
	}
	return encodeLength(w, v.length)
}

// EncodedLen returns the length in bytes of the constructed when encoded
// in DER.
func (v *constructed) EncodedLen() int {
	return len(v.identifier) + encodedLengthSize(v.length) + v.length
}

// Content returns the content of the value.
func (v *constructed) Content() []byte {
	return nil
}
