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
	"bytes"
	"errors"
	"testing"
)

func TestEncodeLength(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		want    []byte
		wantErr bool
	}{
		{
			name:    "Length less than 128",
			length:  127,
			want:    []byte{127},
			wantErr: false,
		},
		{
			name:    "Length equal to 128",
			length:  128,
			want:    []byte{0x81, 128},
			wantErr: false,
		},
		{
			name:    "Length greater than 128",
			length:  300,
			want:    []byte{0x82, 0x01, 0x2C},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			err := encodeLength(buf, tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("encodeLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got := buf.Bytes(); !bytes.Equal(got, tt.want) {
				t.Errorf("encodeLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodedLengthSize(t *testing.T) {
	tests := []struct {
		name   string
		length int
		want   int
	}{
		{
			name:   "Length less than 128",
			length: 127,
			want:   1,
		},
		{
			name:   "Length equal to 128",
			length: 128,
			want:   2,
		},
		{
			name:   "Length greater than 128",
			length: 300,
			want:   3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodedLengthSize(tt.length); got != tt.want {
				t.Errorf("encodedLengthSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

type secondErrorWriter struct {
	count int
}

func (ew *secondErrorWriter) WriteByte(p byte) (err error) {
	ew.count += 1
	if ew.count == 2 {
		return errors.New("write error")
	}
	return nil
}

func TestEncodeLengthFailed(t *testing.T) {
	t.Run("byte write error 1", func(t *testing.T) {
		buf := &errorWriter{}
		err := encodeLength(buf, 128)
		if err == nil {
			t.Error("encodeLength() error = nil, want Error")
			return
		}
	})

	t.Run("byte write error 2", func(t *testing.T) {
		buf := &secondErrorWriter{}
		err := encodeLength(buf, 128)
		if err == nil {
			t.Error("encodeLength() error = nil, want Error")
			return
		}
	})
}
