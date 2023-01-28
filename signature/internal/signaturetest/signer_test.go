package signaturetest

import (
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
)

func TestGetTestLocalSigner(t *testing.T) {
	type args struct {
		keyType signature.KeyType
		size    int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "EC256", args: args{keyType: signature.KeyTypeEC, size: 256}, wantErr: false},
		{name: "EC384", args: args{keyType: signature.KeyTypeEC, size: 384}, wantErr: false},
		{name: "EC521", args: args{keyType: signature.KeyTypeEC, size: 521}, wantErr: false},
		{name: "ECOthers", args: args{keyType: signature.KeyTypeEC, size: 520}, wantErr: true},
		{name: "RSA2048", args: args{keyType: signature.KeyTypeRSA, size: 2048}, wantErr: false},
		{name: "RSA3072", args: args{keyType: signature.KeyTypeRSA, size: 3072}, wantErr: false},
		{name: "RSA4096", args: args{keyType: signature.KeyTypeRSA, size: 4096}, wantErr: false},
		{name: "RSAOthers", args: args{keyType: signature.KeyTypeRSA, size: 4097}, wantErr: true},
		{name: "Others", args: args{keyType: -1, size: 4097}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetTestLocalSigner(tt.args.keyType, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTestLocalSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
