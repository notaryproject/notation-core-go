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

package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-core-go/internal/crypto/cms"
	"github.com/notaryproject/notation-core-go/internal/crypto/pki"
)

// Response is a time-stamping response.
//
//	TimeStampResp ::= SEQUENCE {
//	 status          PKIStatusInfo,
//	 timeStampToken  TimeStampToken  OPTIONAL }
type Response struct {
	Status         pki.StatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// SigningCertificateV2 contains certificates of the TSA.
//
// Reference: RFC 5035 3 SigningCertificateV2
//
//	SigningCertificateV2 ::=  SEQUENCE {
//	 certs        SEQUENCE OF ESSCertIDv2,
//	 policies     SEQUENCE OF PolicyInformation OPTIONAL }
type SigningCertificateV2 struct {
	// Certificates contains the list of certificates. The first certificate
	// MUST be the signing certificate used to verify the timestamp token.
	Certificates []ESSCertIDv2

	// Policies suggests policy values to be used in the certification path
	// validation.
	Policies asn1.RawValue `asn1:"optional"`
}

// ESSCertIDv2 uniquely identifies a certificate.
//
// Reference: RFC 5035 4 ESSCertIDv2
//
//	ESSCertIDv2 ::=  SEQUENCE {
//	 hashAlgorithm           AlgorithmIdentifier
//	 	DEFAULT {algorithm id-sha256},
//	 certHash                 Hash,
//	 issuerSerial             IssuerSerial OPTIONAL }
type ESSCertIDv2 struct {
	// HashAlgorithm is the hashing algorithm used to hash certificate.
	// When it is not present, the default value is SHA256 (id-sha256).
	// SHA1 is unsupported.
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`

	// CertHash is the certificate hash using algorithm identified
	// by HashAlgorithm. It is is computed over the entire DER-encoded
	// certificate (including the signature)
	CertHash []byte

	// IssuerSerial holds the issuer and serialNumber of the certificate
	// When it is not present, the SignerIdentifier field in the SignerInfo
	// will be used.
	IssuerSerial cms.IssuerAndSerialNumber `asn1:"optional"`
}

// MarshalBinary encodes the response to binary form.
// This method implements encoding.BinaryMarshaler.
//
// Reference: https://pkg.go.dev/encoding#BinaryMarshaler
func (r *Response) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil response")
	}
	return asn1.Marshal(*r)
}

// UnmarshalBinary decodes the response from binary form.
// This method implements encoding.BinaryUnmarshaler.
//
// Reference: https://pkg.go.dev/encoding#BinaryUnmarshaler
func (r *Response) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

// ValidateStatus validates the response.Status according to
// https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2
func (r *Response) ValidateStatus() error {
	if r.Status.Status != pki.StatusGranted && r.Status.Status != pki.StatusGrantedWithMods {
		return fmt.Errorf("invalid response with status code: %d", r.Status.Status)
	}
	return nil
}

// SignedToken returns the timestamp token with signatures.
// Callers should invoke Verify to verify the content before comsumption.
func (r *Response) SignedToken() (*SignedToken, error) {
	if err := r.ValidateStatus(); err != nil {
		return nil, err
	}
	return ParseSignedToken(r.TimeStampToken.FullBytes)
}
