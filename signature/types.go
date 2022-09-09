package signature

import "crypto"

// SignatureMediaType list the supported media-type for signatures.
type SignatureMediaType string

// SignatureAlgorithm lists supported signature algorithms.
type SignatureAlgorithm string

// HashAlgorithm algorithm associated with the key spec.
type HashAlgorithm string

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

// One of following supported specs
// https://github.com/notaryproject/notaryproject/blob/main/signature-specification.md#algorithm-selection
const (
	SHA_256 HashAlgorithm = "SHA_256"
	SHA_384 HashAlgorithm = "SHA_384"
	SHA_512 HashAlgorithm = "SHA_512"
)

// HashFunc returns the Hash associated k.
func (h HashAlgorithm) HashFunc() crypto.Hash {
	switch h {
	case SHA_256:
		return crypto.SHA256
	case SHA_384:
		return crypto.SHA384
	case SHA_512:
		return crypto.SHA512
	}
	return 0
}

// Hash returns the Hash associated s.
func (s SignatureAlgorithm) Hash() HashAlgorithm {
	switch s {
	case RSASSA_PSS_SHA_256, ECDSA_SHA_256:
		return SHA_256
	case RSASSA_PSS_SHA_384, ECDSA_SHA_384:
		return SHA_384
	case RSASSA_PSS_SHA_512, ECDSA_SHA_512:
		return SHA_512
	}
	return ""
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
	SigningSchemeX509                 SigningScheme = "notary.x509"
	SigningSchemeX509SigningAuthority SigningScheme = "notary.x509.signingAuthority"
)

// PayloadContentType list the supported content types for signature's  payload .
type PayloadContentType string

const (
	PayloadContentTypeV1 PayloadContentType = "application/vnd.cncf.notary.payload.v1+json"
)
