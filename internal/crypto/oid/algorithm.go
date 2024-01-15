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
)

// ToSignatureAlgorithm converts ASN.1 digest and signature algorithm
// identifiers to golang signature algorithms.
func ToSignatureAlgorithm(digestAlg, sigAlg asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case RSA.Equal(sigAlg):
		switch {
		case SHA256.Equal(digestAlg):
			return x509.SHA256WithRSA
		case SHA384.Equal(digestAlg):
			return x509.SHA384WithRSA
		case SHA512.Equal(digestAlg):
			return x509.SHA512WithRSA
		}
	case SHA256WithRSA.Equal(sigAlg):
		return x509.SHA256WithRSA
	case SHA384WithRSA.Equal(sigAlg):
		return x509.SHA384WithRSA
	case SHA512WithRSA.Equal(sigAlg):
		return x509.SHA512WithRSA
	case ECDSAWithSHA256.Equal(sigAlg):
		return x509.ECDSAWithSHA256
	case ECDSAWithSHA384.Equal(sigAlg):
		return x509.ECDSAWithSHA384
	case ECDSAWithSHA512.Equal(sigAlg):
		return x509.ECDSAWithSHA512
	}
	return x509.UnknownSignatureAlgorithm
}
