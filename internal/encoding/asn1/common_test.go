package asn1

import (
	"bytes"
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
		{
			name:    "Negative length",
			length:  -1,
			want:    nil,
			wantErr: true,
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
