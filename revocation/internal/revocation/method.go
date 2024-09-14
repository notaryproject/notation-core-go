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

// Package revocation provides methods for checking the revocation status of a
// certificate
package revocation

// Method defines the method used to check the revocation status of a
// certificate.
type Method int

const (
	// MethodUnknown is used for root certificates or when the method
	// used to check the revocation status of a certificate is unknown.
	MethodUnknown Method = iota

	// MethodOCSP represents OCSP as the method used to check the
	// revocation status of a certificate.
	MethodOCSP

	// MethodCRL represents CRL as the method used to check the
	// revocation status of a certificate.
	MethodCRL

	// MethodOCSPFallbackCRL represents OCSP check with unknown error
	// fallback to CRL as the method used to check the revocation status of a
	// certificate.
	MethodOCSPFallbackCRL
)

// String provides a conversion from a Method to a string
func (m Method) String() string {
	switch m {
	case MethodOCSP:
		return "OCSP"
	case MethodCRL:
		return "CRL"
	case MethodOCSPFallbackCRL:
		return "OCSPFallbackCRL"
	default:
		return "Unknown"
	}
}
