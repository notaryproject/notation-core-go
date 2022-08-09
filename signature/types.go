package signature

import (
	"crypto/x509"
	"time"
)

// MediaTypePayloadV1 is the supported content type for signature's payload
const MediaTypePayloadV1 = "application/vnd.cncf.notary.payload.v1+json"

// SignedAttributes represents signed metadata in the Signature envelope
type SignedAttributes struct {
	SigningTime        time.Time
	Expiry             time.Time
	ExtendedAttributes []Attribute
}

// UnsignedAttributes represents unsigned metadata in the Signature envelope
type UnsignedAttributes struct {
	SigningAgent string
}

// Attribute represents metadata in the Signature envelope
type Attribute struct {
	Key      string
	Critical bool
	Value    interface{}
}

// SignRequest is used to generate Signature.
type SignRequest struct {
	Payload                  Payload
	Signer                   Signer
	SigningTime              time.Time
	Expiry                   time.Time
	ExtendedSignedAttributes []Attribute
	SigningAgent             string
}

// SignerInfo represents a parsed signature envelope that is agnostic to signature
// envelope format.
type SignerInfo struct {
	SignedAttributes   SignedAttributes
	UnsignedAttributes UnsignedAttributes
	SignatureAlgorithm Algorithm
	CertificateChain   []*x509.Certificate
	Signature          []byte
	TimestampSignature []byte
}

// Payload represents payload in bytes and its content type
type Payload struct {
	ContentType string
	Content     []byte
}
