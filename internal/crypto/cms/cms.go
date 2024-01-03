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

// Package cms verifies signatures in Cryptographic Message Syntax (CMS) / PKCS7
// defined in RFC 5652.
//
// References:
// - RFC 5652 Cryptographic Message Syntax (CMS): https://datatracker.ietf.org/doc/html/rfc5652
package cms

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// ContentInfo struct is used to represent the content of a CMS message,
// which can be encrypted, signed, or both.
//
// References: RFC 5652 3 ContentInfo Type
//
//	ContentInfo ::= SEQUENCE {
//	  contentType ContentType,
//	  content [0] EXPLICIT ANY DEFINED BY contentType }
type ContentInfo struct {
	// ContentType field specifies the type of the content, which can be one of
	// several predefined types, such as data, signedData, envelopedData, or
	// encryptedData. Only signedData is supported currently.
	ContentType asn1.ObjectIdentifier

	// Content field contains the actual content of the message.
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

// SignedData struct is used to represent a signed CMS message, which contains
// one or more signatures that are used to verify the authenticity and integrity
// of the message.
//
// Reference: RFC 5652 5.1 SignedData
//
//	SignedData ::= SEQUENCE {
//	 version             CMSVersion,
//	 digestAlgorithms    DigestAlgorithmIdentifiers,
//	 encapContentInfo    EncapsulatedContentInfo,
//	 certificates        [0] IMPLICIT CertificateSet             OPTIONAL,
//	 crls                [1] IMPLICIT CertificateRevocationLists OPTIONAL,
//	 signerInfos         SignerInfos }
type SignedData struct {
	// Version field specifies the syntax version number of the SignedData.
	Version int

	// DigestAlgorithmIdentifiers field specifies the digest algorithms used
	// by one or more signatures in SignerInfos.
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`

	// EncapsulatedContentInfo field specifies the content that is signed.
	EncapsulatedContentInfo EncapsulatedContentInfo

	// Certificates field contains the certificates that are used to verify the
	// signatures in SignerInfos.
	Certificates asn1.RawValue `asn1:"optional,tag:0"`

	// CRLs field contains the Certificate Revocation Lists that are used to
	// verify the signatures in SignerInfos.
	CRLs []x509.RevocationList `asn1:"optional,tag:1"`

	// SignerInfos field contains one or more signatures.
	SignerInfos []SignerInfo `asn1:"set"`
}

// EncapsulatedContentInfo struct is used to represent the content of a CMS
// message.
//
// References: RFC 5652 5.2 EncapsulatedContentInfo
//
//	EncapsulatedContentInfo ::= SEQUENCE {
//	 eContentType    ContentType,
//	 eContent        [0] EXPLICIT OCTET STRING   OPTIONAL }
type EncapsulatedContentInfo struct {
	// ContentType is an object identifier. The object identifier uniquely
	// specifies the content type.
	ContentType asn1.ObjectIdentifier

	// Content field contains the actual content of the message.
	Content []byte `asn1:"explicit,optional,tag:0"`
}

// SignerInfo struct is used to represent a signature and related information
// that is needed to verify the signature.
//
// Reference: RFC 5652 5.3 SignerInfo
//
//	SignerInfo ::= SEQUENCE {
//	 version             CMSVersion,
//	 sid                 SignerIdentifier,
//	 digestAlgorithm     DigestAlgorithmIdentifier,
//	 signedAttrs         [0] IMPLICIT SignedAttributes   OPTIONAL,
//	 signatureAlgorithm  SignatureAlgorithmIdentifier,
//	 signature           SignatureValue,
//	 unsignedAttrs       [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// Only version 1 is supported. As defined in RFC 5652 5.3, SignerIdentifier
// is IssuerAndSerialNumber when version is 1.
type SignerInfo struct {
	// Version field specifies the syntax version number of the SignerInfo.
	Version int

	// SignerIdentifier field specifies the signer's certificate. Only IssuerAndSerialNumber
	// is supported currently.
	SignerIdentifier IssuerAndSerialNumber

	// DigestAlgorithm field specifies the digest algorithm used by the signer.
	DigestAlgorithm pkix.AlgorithmIdentifier

	// SignedAttributes field contains a collection of attributes that are
	// signed.
	SignedAttributes Attributes `asn1:"optional,tag:0"`

	// SignatureAlgorithm field specifies the signature algorithm used by the
	// signer.
	SignatureAlgorithm pkix.AlgorithmIdentifier

	// Signature field contains the actual signature.
	Signature []byte

	// UnsignedAttributes field contains a collection of attributes that are
	// not signed.
	UnsignedAttributes Attributes `asn1:"optional,tag:1"`
}

// IssuerAndSerialNumber struct is used to identify a certificate.
//
// Reference: RFC 5652 5.3 SignerIdentifier
//
//	IssuerAndSerialNumber ::= SEQUENCE {
//	 issuer          Name,
//	 serialNumber    CertificateSerialNumber }
type IssuerAndSerialNumber struct {
	// Issuer field identifies the certificate issuer.
	Issuer asn1.RawValue

	// SerialNumber field identifies the certificate.
	SerialNumber *big.Int
}

// Attributes struct is used to represent a collection of attributes.
//
// Reference: RFC 5652 5.3 SignerInfo
//
//	Attribute ::= SEQUENCE {
//	  attrType    OBJECT IDENTIFIER,
//	  attrValues  SET OF AttributeValue }
type Attribute struct {
	// Type field specifies the type of the attribute.
	Type asn1.ObjectIdentifier

	// Values field contains the actual value of the attribute.
	Values asn1.RawValue `asn1:"set"`
}

// Attribute ::= SET SIZE (1..MAX) OF Attribute
type Attributes []Attribute

// TryGet tries to find the attribute by the given identifier, parse and store
// the result in the value pointed to by out.
func (a *Attributes) TryGet(identifier asn1.ObjectIdentifier, out interface{}) error {
	for _, attribute := range *a {
		if identifier.Equal(attribute.Type) {
			_, err := asn1.Unmarshal(attribute.Values.Bytes, out)
			return err
		}
	}
	return ErrAttributeNotFound
}
