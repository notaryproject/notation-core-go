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

// Package oid collects object identifiers for crypto algorithms.
package oid

import "encoding/asn1"

// OIDs for hash algorithms
var (
	// SHA256 (id-sha256) is defined in RFC 8017 B.1 Hash Functions
	SHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	// SHA384 (id-sha384) is defined in RFC 8017 B.1 Hash Functions
	SHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}

	// SHA512 (id-sha512) is defined in RFC 8017 B.1 Hash Functions
	SHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// OIDs for signature algorithms
var (
	// RSA is defined in RFC 8017 C ASN.1 Module
	RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// SHA256WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

	// SHA384WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}

	// SHA512WithRSA is defined in RFC 8017 C ASN.1 Module
	SHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	// ECDSAWithSHA256 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	// ECDSAWithSHA384 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}

	// ECDSAWithSHA512 is defined in RFC 5758 3.2 ECDSA Signature Algorithm
	ECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// OIDs defined in RFC 5652 Cryptographic Message Syntax (CMS)
var (
	// Data (id-data) is defined in RFC 5652 4 Data Content Type
	Data = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	// SignedData (id-signedData) is defined in RFC 5652 5.1 SignedData Type
	SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// ContentType (id-ct-contentType) is defined in RFC 5652 3 General Syntax
	ContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}

	// MessageDigest (id-messageDigest) is defined in RFC 5652 11.2 Message Digest
	MessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// SigningTime (id-signingTime) is defined in RFC 5652 11.3 Signing Time
	SigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)
