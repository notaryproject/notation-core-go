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
