package signer

import "crypto"

// SignatureMediaType list the supported media-type for signatures.
type SignatureMediaType string

// SignatureAlgorithm lists supported signature algorithms.
type SignatureAlgorithm string

// One of following supported specs
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	RSASSA_PSS_SHA_256 SignatureAlgorithm = "RSASSA_PSS_SHA_256"
	RSASSA_PSS_SHA_384 SignatureAlgorithm = "RSASSA_PSS_SHA_384"
	RSASSA_PSS_SHA_512 SignatureAlgorithm = "RSASSA_PSS_SHA_512"
	ECDSA_SHA_256      SignatureAlgorithm = "ECDSA_SHA_256"
	ECDSA_SHA_384      SignatureAlgorithm = "ECDSA_SHA_384"
	ECDSA_SHA_512      SignatureAlgorithm = "ECDSA_SHA_512"
)

// Hash returns the Hash associated s.
func (s SignatureAlgorithm) Hash() crypto.Hash {
	var hash crypto.Hash
	switch s {
	case RSASSA_PSS_SHA_256, ECDSA_SHA_256:
		hash = crypto.SHA256
	case RSASSA_PSS_SHA_384, ECDSA_SHA_384:
		hash = crypto.SHA384
	case RSASSA_PSS_SHA_512, ECDSA_SHA_512:
		hash = crypto.SHA512
	}
	return hash
}

// KeySpec defines a key type and size.
type KeySpec string

const (
	RSA_2048 KeySpec = "RSA_2048"
	RSA_3072 KeySpec = "RSA_3072"
	RSA_4096 KeySpec = "RSA_4096"
	EC_256   KeySpec = "EC_256"
	EC_384   KeySpec = "EC_384"
	EC_521   KeySpec = "EC_521"
)

// SignatureAlgorithm returns the signing algorithm associated with KeyType k.
func (k KeySpec) SignatureAlgorithm() SignatureAlgorithm {
	switch k {
	case RSA_2048:
		return RSASSA_PSS_SHA_256
	case RSA_3072:
		return RSASSA_PSS_SHA_384
	case RSA_4096:
		return RSASSA_PSS_SHA_512
	case EC_256:
		return ECDSA_SHA_256
	case EC_384:
		return ECDSA_SHA_384
	case EC_521:
		return ECDSA_SHA_512
	}
	return ""
}

// SigningScheme formalizes the feature set (guarantees) provided by the signature.
type SigningScheme string

const (
	SigningSchemeX509Default          SigningScheme = "notary.default.x509"
	SigningSchemeX509SigningAuthority SigningScheme = "notary.signingAuthority.x509"
)

// PayloadContentType list the supported content types for signature's  payload .
type PayloadContentType string

const (
	PayloadContentTypeV1 PayloadContentType = "application/vnd.cncf.notary.payload.v1+json"
)
