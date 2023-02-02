// Package signaturetest includes variables and functions for signature
// unit test.
package signaturetest

import (
	"reflect"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
)

func TestGetKeySizes(t *testing.T) {
	type args struct {
		keyType signature.KeyType
	}
	tests := []struct {
		name string
		args args
		want []int
	}{
		{name: "RSA", args: args{keyType: signature.KeyTypeRSA}, want: []int{2048, 3072, 4096}},
		{name: "EC", args: args{keyType: signature.KeyTypeEC}, want: []int{256, 384, 521}},
		{name: "others", args: args{keyType: -1}, want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetKeySizes(tt.args.keyType); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetKeySizes() = %v, want %v", got, tt.want)
			}
		})
	}
}
