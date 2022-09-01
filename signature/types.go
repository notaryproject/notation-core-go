package signature

import (
	"time"
)

// MediaTypePayloadV1 is the supported content type for signature's payload.
const MediaTypePayloadV1 = "application/vnd.cncf.notary.payload.v1+json"

// SigningScheme formalizes the feature set (guarantees) provided by
// the signature.
// Reference: https://github.com/notaryproject/notaryproject/blob/main/signing-scheme.md
type SigningScheme string

// SigningSchemes supported by notation.
const (
	// notary.x509 signing scheme.
	SigningSchemeX509 SigningScheme = "notary.x509"

	// notary.x509.signingAuthority schema.
	SigningSchemeX509SigningAuthority SigningScheme = "notary.x509.signingAuthority"
)

// Attribute represents metadata in the Signature envelope.
type Attribute struct {
	// Key is the key name of the attribute.
	Key string

	// Critical marks the attribute that MUST be processed by a verifier.
	Critical bool

	// Value is the value of the attribute.
	Value interface{}
}

// SignRequest is used to generate Signature.
type SignRequest struct {
	// Payload is the payload to be signed.
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

	// SigningScheme defines the Notary v2 Signing Scheme used by the signature.
	SigningScheme SigningScheme
}
