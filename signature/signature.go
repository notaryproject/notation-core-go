package signature

import (
	"crypto/x509"
	"fmt"
	"time"
)

// SignatureEnvelope reprents an signature envelope and agnostic to signature envelope format.
type SignatureEnvelope struct {
	Payload            []byte
	PayloadContentType string
	SignatureAlgorithm SignatureAlgorithm
	CertificateChain   x509.CertPool
	Signature          []byte
	TimestampSignature []byte

	SignedAttributes   SignedAttributes
	UnsignedAttributes UnsignedAttributes
}

// S
type SignedAttributes struct {
	SigningTime time.Time // library will take care critical/presence
	Expiry      time.Time // library will take care critical/presence
	Custom      []Attributes
}

type UnsignedAttributes struct {
	SignignAgent string
}

type Attributes struct {
	Key      string
	Critical bool
	Value    interface{}
}

// List of supported signature algorithms.
type SignatureAlgorithm string

const (
	RSASSA_PSS_SHA_256 SignatureAlgorithm = "RSASSA_PSS_SHA_256"
	RSASSA_PSS_SHA_384 SignatureAlgorithm = "RSASSA_PSS_SHA_384"
	RSASSA_PSS_SHA_512 SignatureAlgorithm = "RSASSA_PSS_SHA_512"
	ECDSA_SHA_256      SignatureAlgorithm = "ECDSA_SHA_256"
	ECDSA_SHA_384      SignatureAlgorithm = "ECDSA_SHA_384"
	ECDSA_SHA_512      SignatureAlgorithm = "ECDSA_SHA_512"
)

// SignatureParser provides methods to parse and validate signature integrity.
type SignatureParser interface {
	// validateIntegrity validates the integrity of signature envelopes and parses it.
	// Throws two kinds of error message depending upon kind of failure
	// 1. MalformedSignatureError - When signature envelope is malformed and cannot be read/interpreted
	// 2. InvalidSignatureError - When signature is not valid i.e integrity check failed.
	validateIntegrity(envelopeBytes []byte) (SignatureEnvelope, error)
}

// Verifier provides methods for integrity and cert-chain validations.
type Verifier struct {
	parser SignatureParser
}

// Verify methods validates the signature integrity and performs cert-chain related validations.
func (verifier *Verifier) Verify(envelopeBytes []byte, trustedCertificates x509.CertPool) (SignatureEnvelope, error) {
	fmt.Println("Verify")
	signatureEnvelope, _ := verifier.parser.validateIntegrity(envelopeBytes)
	return signatureEnvelope, nil
}

// Note: Critical part
