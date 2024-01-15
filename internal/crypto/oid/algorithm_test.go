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

package oid

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

func TestToSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name       string
		digestAlg  asn1.ObjectIdentifier
		sigAlg     asn1.ObjectIdentifier
		wantResult x509.SignatureAlgorithm
	}{
		{"SHA256WithRSA", SHA256, RSA, x509.SHA256WithRSA},
		{"SHA384WithRSA", SHA384, RSA, x509.SHA384WithRSA},
		{"SHA512WithRSA", SHA512, RSA, x509.SHA512WithRSA},
		{"SHA256WithRSA direct", SHA256WithRSA, SHA256WithRSA, x509.SHA256WithRSA},
		{"SHA384WithRSA direct", SHA384WithRSA, SHA384WithRSA, x509.SHA384WithRSA},
		{"SHA512WithRSA direct", SHA512WithRSA, SHA512WithRSA, x509.SHA512WithRSA},
		{"ECDSAWithSHA256", ECDSAWithSHA256, ECDSAWithSHA256, x509.ECDSAWithSHA256},
		{"ECDSAWithSHA384", ECDSAWithSHA384, ECDSAWithSHA384, x509.ECDSAWithSHA384},
		{"ECDSAWithSHA512", ECDSAWithSHA512, ECDSAWithSHA512, x509.ECDSAWithSHA512},
		{"UnknownSignatureAlgorithm", asn1.ObjectIdentifier{1, 2, 3}, asn1.ObjectIdentifier{4, 5, 6}, x509.UnknownSignatureAlgorithm},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotResult := ToSignatureAlgorithm(tt.digestAlg, tt.sigAlg); gotResult != tt.wantResult {
				t.Errorf("ToSignatureAlgorithm() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}
