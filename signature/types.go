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

package signature

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/notaryproject/tspclient-go"
)

// SignatureMediaType list the supported media-type for signatures.
type SignatureMediaType string

// SigningScheme formalizes the feature set (guarantees) provided by
// the signature.
// Reference: https://github.com/notaryproject/notaryproject/blob/main/specs/signing-scheme.md
type SigningScheme string

// SigningSchemes supported by notation.
const (
	// notary.x509 signing scheme.
	SigningSchemeX509 SigningScheme = "notary.x509"

	// notary.x509.signingAuthority schema.
	SigningSchemeX509SigningAuthority SigningScheme = "notary.x509.signingAuthority"
)

// SignedAttributes represents signed metadata in the signature envelope.
// Reference: https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#signed-attributes
type SignedAttributes struct {
	// SigningScheme defines the Notary Project Signing Scheme used by the signature.
	SigningScheme SigningScheme

	// SigningTime indicates the time at which the signature was generated.
	SigningTime time.Time

	// Expiry provides a “best by use” time for the artifact.
	Expiry time.Time

	// additional signed attributes in the signature envelope.
	ExtendedAttributes []Attribute
}

// UnsignedAttributes represents unsigned metadata in the Signature envelope.
// Reference: https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#unsigned-attributes
type UnsignedAttributes struct {
	// TimestampSignature is a counter signature providing authentic timestamp.
	TimestampSignature []byte

	// SigningAgent provides the identifier of the software (e.g. Notation) that
	// produces the signature on behalf of the user.
	SigningAgent string
}

// Attribute represents metadata in the Signature envelope.
type Attribute struct {
	// Key is the key name of the attribute.
	Key any

	// Critical marks the attribute that MUST be processed by a verifier.
	Critical bool

	// Value is the value of the attribute.
	Value any
}

// SignRequest is used to generate Signature.
type SignRequest struct {
	// Payload is the payload to be signed.
	//
	// For JWS envelope, Payload.Content is limited to be JSON format.
	Payload Payload

	// Signer is the signer used to sign the digest.
	Signer Signer

	// SigningTime is the time at which the signature was generated.
	SigningTime time.Time

	// Expiry provides a “best by use” time for the artifact.
	Expiry time.Time

	// ExtendedSignedAttributes is additional signed attributes in the
	// signature envelope.
	ExtendedSignedAttributes []Attribute

	// SigningAgent provides the identifier of the software (e.g. Notation)
	// that produced the signature on behalf of the user.
	SigningAgent string

	// SigningScheme defines the Notary Project Signing Scheme used by the signature.
	SigningScheme SigningScheme

	// Timestamper denotes the timestamper for RFC 3161 timestamping
	Timestamper tspclient.Timestamper

	// TSARootCAs is the set of caller trusted TSA root certificates
	TSARootCAs *x509.CertPool

	// ctx is the caller context. It should only be modified via WithContext.
	// It is unexported to prevent people from using Context wrong
	// and mutating the contexts held by callers of the same request.
	ctx context.Context
}

// Context returns the SignRequest's context. To change the context, use
// [SignRequest.WithContext].
//
// The returned context is always non-nil; it defaults to the
// background context.
func (r *SignRequest) Context() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}

// WithContext returns a shallow copy of r with its context changed
// to ctx. The provided ctx must be non-nil.
func (r *SignRequest) WithContext(ctx context.Context) *SignRequest {
	if ctx == nil {
		panic("nil context")
	}
	r2 := new(SignRequest)
	*r2 = *r
	r2.ctx = ctx
	return r2
}

// EnvelopeContent represents a combination of payload to be signed and a parsed
// signature envelope.
type EnvelopeContent struct {
	// SignerInfo is a parsed signature envelope.
	SignerInfo SignerInfo

	// Payload is payload to be signed.
	Payload Payload
}

// SignerInfo represents a parsed signature envelope that is agnostic to
// signature envelope format.
type SignerInfo struct {
	// SignedAttributes are additional metadata required to support the
	// signature verification process.
	SignedAttributes SignedAttributes

	// UnsignedAttributes are considered unsigned with respect to the signing
	// key that generates the signature.
	UnsignedAttributes UnsignedAttributes

	// SignatureAlgorithm defines the signature algorithm.
	SignatureAlgorithm Algorithm

	// CertificateChain is an ordered list of X.509 public certificates
	// associated with the signing key used to generate the signature.
	// The ordered list starts with the signing certificates, any intermediate
	// certificates and ends with the root certificate.
	CertificateChain []*x509.Certificate

	// Signature is the bytes generated from the signature.
	Signature []byte
}

// Payload represents payload in bytes and its content type.
type Payload struct {
	// ContentType specifies the content type of payload.
	ContentType string

	// Content contains the raw bytes of the payload.
	//
	// For JWS envelope, Content is limited to be JSON format.
	Content []byte
}

// ExtendedAttribute fetches the specified Attribute with provided key from
// signerInfo.SignedAttributes.ExtendedAttributes.
func (signerInfo *SignerInfo) ExtendedAttribute(key string) (Attribute, error) {
	for _, attr := range signerInfo.SignedAttributes.ExtendedAttributes {
		if attr.Key == key {
			return attr, nil
		}
	}
	return Attribute{}, errors.New("key not in ExtendedAttributes")
}

// AuthenticSigningTime returns the authentic signing time
func (signerInfo *SignerInfo) AuthenticSigningTime() (time.Time, error) {
	switch signerInfo.SignedAttributes.SigningScheme {
	case SigningSchemeX509SigningAuthority:
		return signerInfo.SignedAttributes.SigningTime, nil
	case SigningSchemeX509:
		if len(signerInfo.UnsignedAttributes.TimestampSignature) > 0 {
			// TODO: Add TSA support for AutheticSigningTime
			// https://github.com/notaryproject/notation-core-go/issues/38
			return time.Time{}, errors.New("TSA checking has not been implemented")
		}
	}
	return time.Time{}, errors.New("authenticSigningTime not found")
}
