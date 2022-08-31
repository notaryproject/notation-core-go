package jws

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signature"
)

const (
	headerKeyAlg                  = "alg"
	headerKeyCty                  = "cty"
	headerKeyCrit                 = "crit"
	headerKeyExpiry               = "io.cncf.notary.expiry"
	headerKeySigningTime          = "io.cncf.notary.signingTime"
	headerKeySigningScheme        = "io.cncf.notary.signingScheme"
	headerKeyAuthenticSigningTime = "io.cncf.notary.authenticSigningTime"
)

var headerKeys = []string{
	headerKeyAlg,
	headerKeyCty,
	headerKeyCrit,
	headerKeyExpiry,
	headerKeySigningTime,
	headerKeySigningScheme,
	headerKeyAuthenticSigningTime,
}

// jwsProtectedHeader contains the set of protected headers.
type jwsProtectedHeader struct {
	// Defines which algorithm was used to generate the signature.
	Algorithm string `json:"alg"`

	// Media type of the secured content (the payload).
	ContentType string `json:"cty"`

	// Lists the headers that implementation MUST understand and process.
	Critical []string `json:"crit,omitempty"`

	// The "best by use" time for the artifact, as defined by the signer.
	Expiry *time.Time `json:"io.cncf.notary.expiry,omitempty"`

	// Specifies the Notary v2 Signing Scheme used by the signature.
	SigningScheme signature.SigningScheme `json:"io.cncf.notary.signingScheme"`

	// The time at which the signature was generated. only valid when signing scheme is `notary.x509`
	SigningTime *time.Time `json:"io.cncf.notary.signingTime,omitempty"`

	// The time at which the signature was generated. only valid when signing scheme is `notary.x509.signingAuthority`
	AuthenticSigningTime *time.Time `json:"io.cncf.notary.authenticSigningTime,omitempty"`

	// The user defined attributes.
	ExtendedAttributes map[string]interface{} `json:"-"`
}

// jwsUnprotectedHeader contains the set of unprotected headers.
type jwsUnprotectedHeader struct {
	// RFC3161 time stamp token Base64-encoded.
	TimestampSignature []byte `json:"io.cncf.notary.timestampSignature,omitempty"`

	// List of X.509 Base64-DER-encoded certificates
	// as defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6.
	CertChain [][]byte `json:"x5c"`

	// SigningAgent used for signing
	SigningAgent string `json:"io.cncf.notary.signingAgent,omitempty"`
}

// jwsEnvelope is the final Signature envelope.
type jwsEnvelope struct {
	// JWSPayload Base64URL-encoded. Raw data should be JSON format.
	Payload string `json:"payload"`

	// jwsProtectedHeader Base64URL-encoded.
	Protected string `json:"protected"`

	// Signature metadata that is not integrity Protected
	Header jwsUnprotectedHeader `json:"header"`

	// Base64URL-encoded Signature.
	Signature string `json:"signature"`
}

var (
	ps256 = jwt.SigningMethodPS256.Name
	ps384 = jwt.SigningMethodPS384.Name
	ps512 = jwt.SigningMethodPS512.Name
	es256 = jwt.SigningMethodES256.Name
	es384 = jwt.SigningMethodES384.Name
	es512 = jwt.SigningMethodES512.Name
)

var validMethods = []string{ps256, ps384, ps512, es256, es384, es512}

var signatureAlgJWSAlgMap = map[signature.Algorithm]string{
	signature.AlgorithmPS256: ps256,
	signature.AlgorithmPS384: ps384,
	signature.AlgorithmPS512: ps512,
	signature.AlgorithmES256: es256,
	signature.AlgorithmES384: es384,
	signature.AlgorithmES512: es512,
}

var jwsAlgSignatureAlgMap = reverseMap(signatureAlgJWSAlgMap)

func reverseMap(m map[signature.Algorithm]string) map[string]signature.Algorithm {
	n := make(map[string]signature.Algorithm, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}
