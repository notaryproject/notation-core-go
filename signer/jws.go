package signer

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	MediaTypeJWSJson SignatureMediaType = "application/jose+json"
)

const (
	headerKeyExpiry      = "io.cncf.notary.expiry"
	headerKeySigningTime = "io.cncf.notary.signingTime"
	headerKeyCrit        = "crit"
	headerKeyAlg         = "alg"
	headerKeyCty         = "cty"
)

// jwsEnvelope represents implements internalSignatureEnvelope interface.
type jwsEnvelope struct {
	internalEnv *jwsInternalEnvelope
}

func newJWSEnvelopeFromBytes(envelopeBytes []byte) (*jwsEnvelope, error) {
	jwsInternal, err := newJwsInternalEnvelopeFromBytes(envelopeBytes)
	if err != nil {
		return nil, err
	}

	return &jwsEnvelope{internalEnv: jwsInternal}, nil
}

func (jws *jwsEnvelope) validateIntegrity() error {
	if jws.internalEnv == nil {
		return SignatureNotFoundError{}
	}

	if len(jws.internalEnv.Header.CertChain) == 0 {
		return MalformedSignatureError{msg: "malformed leaf certificate"}
	}

	cert, err := x509.ParseCertificate(jws.internalEnv.Header.CertChain[0])
	if err != nil {
		return MalformedSignatureError{msg: "malformed leaf certificate"}
	}

	// verify JWT
	compact := strings.Join([]string{jws.internalEnv.Protected, jws.internalEnv.Payload, jws.internalEnv.Signature}, ".")
	return verifyJWT(compact, cert.PublicKey)
}

func (jws *jwsEnvelope) signPayload(req SignRequest) ([]byte, error) {
	leafPublicKey := req.CertificateChain[0].PublicKey
	var m map[string]interface{}
	if err := json.Unmarshal(req.Payload, &m); err != nil {
		return nil, err
	}
	signingMethod, err := getSigningMethod(leafPublicKey)
	if err != nil {
		return nil, err
	}

	signedAttrs, err := getSignedAttrs(req, signingMethod)
	if err != nil {
		return nil, err
	}

	compact, err := signJWT(m, signedAttrs, signingMethod, req.SignatureProvider)
	if err != nil {
		return nil, err
	}

	j, err := generateJws(compact, req)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(j)
	if err != nil {
		return nil, err
	}
	jws.internalEnv = j
	return b, nil
}

func (jws *jwsEnvelope) getSignerInfo() (*SignerInfo, error) {
	signInfo := SignerInfo{}
	if jws.internalEnv == nil {
		return nil, SignatureNotFoundError{}
	}

	// parse payload
	payload, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Payload)
	if err != nil {
		return nil, err
	}
	signInfo.Payload = payload

	// parse protected headers
	protected, err := parseProtectedHeaders(jws.internalEnv.Protected)
	if err != nil {
		return nil, err
	}
	if err := populateProtectedHeaders(protected, &signInfo); err != nil {
		return nil, err
	}

	// parse signature
	sig, err := base64.RawURLEncoding.DecodeString(jws.internalEnv.Signature)
	if err != nil {
		return nil, err
	}
	signInfo.Signature = sig

	// parse headers
	var certs []*x509.Certificate
	for _, certBytes := range jws.internalEnv.Header.CertChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	signInfo.CertificateChain = certs
	signInfo.UnsignedAttributes.SigningAgent = jws.internalEnv.Header.SigningAgent
	signInfo.TimestampSignature = jws.internalEnv.Header.TimestampSignature

	return &signInfo, nil
}

func parseProtectedHeaders(encoded string) (*jwsProtectedHeader, error) {
	rawProtected, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, MalformedSignatureError{msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}

	var protected jwsProtectedHeader
	if err = json.Unmarshal(rawProtected, &protected); err != nil {
		return nil, MalformedSignatureError{msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}
	if err = json.Unmarshal(rawProtected, &protected.ExtendedAttributes); err != nil {
		return nil, MalformedSignatureError{msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}

	// delete attributes that are already defined in jwsProtectedHeader.
	delete(protected.ExtendedAttributes, headerKeyAlg)
	delete(protected.ExtendedAttributes, headerKeyCty)
	delete(protected.ExtendedAttributes, headerKeyCrit)
	delete(protected.ExtendedAttributes, headerKeySigningTime)
	delete(protected.ExtendedAttributes, headerKeyExpiry)

	return &protected, nil
}

func populateProtectedHeaders(pHeader *jwsProtectedHeader, signInfo *SignerInfo) error {
	err := validateCriticalHeaders(pHeader)
	if err != nil {
		return err
	}

	if signInfo.SignatureAlgorithm, err = getAlgo(pHeader.Algorithm); err != nil {
		return err
	}

	signInfo.PayloadContentType = pHeader.ContentType
	signInfo.SignedAttributes.SigningTime = pHeader.SigningTime.Truncate(time.Second)
	signInfo.SignedAttributes.Expiry = pHeader.Expiry.Truncate(time.Second)
	signInfo.SignedAttributes.ExtendedAttributes = getExtendedAttributes(pHeader.ExtendedAttributes, pHeader.Critical)
	return nil
}

func getExtendedAttributes(attrs map[string]interface{}, critical []string) []Attribute {
	extendedAttr := make([]Attribute, 0, len(attrs))
	for key, value := range attrs {
		extendedAttr = append(extendedAttr, Attribute{
			Key:      key,
			Critical: contains(critical, key),
			Value:    value,
		})
	}
	return extendedAttr
}

func validateCriticalHeaders(pheader *jwsProtectedHeader) error {
	if len(pheader.Critical) == 0 {
		return MalformedSignatureError{"missing `crit` header"}
	}

	mustMarkedCrit := map[string]bool{}
	if !pheader.Expiry.IsZero() {
		mustMarkedCrit[headerKeyExpiry] = true
	}

	for _, val := range pheader.Critical {
		if _, ok := mustMarkedCrit[val]; ok {
			delete(mustMarkedCrit, val)
		} else {
			if _, ok := pheader.ExtendedAttributes[val]; !ok {
				return MalformedSignatureError{msg: fmt.Sprintf("%q header is marked critical but not present", val)}
			}
		}
	}

	// validate all required critical headers are present.
	if len(mustMarkedCrit) != 0 {
		// This is not taken care by VerifySignerInfo method
		return MalformedSignatureError{"required headers not marked critical"}
	}

	return nil
}

func getSignedAttrs(req SignRequest, method jwt.SigningMethod) (map[string]interface{}, error) {
	extAttrs := make(map[string]interface{})
	var crit []string
	if !req.Expiry.IsZero() {
		crit = append(crit, headerKeyExpiry)
	}

	for _, elm := range req.ExtendedSignedAttrs {
		extAttrs[elm.Key] = elm.Value
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
	}

	pHeader := jwsProtectedHeader{
		Algorithm:   method.Alg(),
		ContentType: req.PayloadContentType,
		Critical:    crit,
		SigningTime: req.SigningTime.Truncate(time.Second),
	}
	if !req.Expiry.IsZero() {
		pHeader.Expiry = req.Expiry.Truncate(time.Second)
	}

	m, err := convertToMap(pHeader)
	if err != nil {
		return nil, MalformedSignRequestError{msg: fmt.Sprintf("unexpected error occured while creating protected headers, Error: %s", err.Error())}
	}

	return mergeMaps(m, extAttrs), nil
}

// ***********************************************************************
// jwsEnvelope-JSON specific code
// ***********************************************************************
const (
	// PayloadContentTypeJWSV1 describes the media type of the jwsEnvelope envelope.
	PayloadContentTypeJWSV1 = "application/vnd.cncf.notary.v2.jws.v1"
)

// jwsInternalEnvelope is the final Signature envelope.
type jwsInternalEnvelope struct {
	// JWSPayload Base64URL-encoded.
	Payload string `json:"payload"`

	// jwsProtectedHeader Base64URL-encoded.

	Protected string `json:"protected"`

	// Signature metadata that is not integrity Protected
	Header jwsUnprotectedHeader `json:"header"`

	// Base64URL-encoded Signature.
	Signature string `json:"signature"`
}

// jwsProtectedHeader contains the set of protected headers.
type jwsProtectedHeader struct {
	// Defines which algorithm was used to generate the signature.
	Algorithm string `json:"alg"`

	// Media type of the secured content (the payload).
	ContentType string `json:"cty"`

	// Lists the headers that implementation MUST understand and process.
	Critical []string `json:"crit"`

	// The time at which the signature was generated.
	SigningTime time.Time `json:"io.cncf.notary.signingTime"`

	// The "best by use" time for the artifact, as defined by the signer.
	Expiry time.Time `json:"io.cncf.notary.expiry,omitempty"`

	// The user defined attributes.
	ExtendedAttributes map[string]interface{} `json:"-"`
}

// jwsUnprotectedHeader contains the set of unprotected headers.
type jwsUnprotectedHeader struct {
	// RFC3161 time stamp token Base64-encoded.
	TimestampSignature []byte `json:"io.cncf.notary.TimestampSignature,omitempty"`

	// List of X.509 Base64-DER-encoded certificates
	// as defined at https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6.
	CertChain [][]byte `json:"x5c"`

	// SigningAgent used for signing
	SigningAgent string `json:"io.cncf.notary.SigningAgent,omitempty"`
}

func newJwsInternalEnvelopeFromBytes(b []byte) (*jwsInternalEnvelope, error) {
	var jws jwsInternalEnvelope
	if err := json.Unmarshal(b, &jws); err != nil {
		return nil, err
	}
	return &jws, nil
}

func generateJws(compact string, req SignRequest) (*jwsInternalEnvelope, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		// this should never happen
		return nil, errors.New("unexpected error while generating a JWS-JSON serialization from compact serialization")
	}

	rawCerts := make([][]byte, len(req.CertificateChain))
	for i, cert := range req.CertificateChain {
		rawCerts[i] = cert.Raw
	}

	return &jwsInternalEnvelope{
		Protected: parts[0],
		Payload:   parts[1],
		Signature: parts[2],
		Header: jwsUnprotectedHeader{
			CertChain:    rawCerts,
			SigningAgent: req.SigningAgent,
		},
	}, nil
}

func getAlgo(alg string) (SignatureAlgorithm, error) {
	switch alg {
	case "PS256":
		return RSASSA_PSS_SHA_256, nil
	case "PS384":
		return RSASSA_PSS_SHA_384, nil
	case "PS512":
		return RSASSA_PSS_SHA_512, nil
	case "ES256":
		return ECDSA_SHA_256, nil
	case "ES384":
		return ECDSA_SHA_384, nil
	case "ES512":
		return ECDSA_SHA_512, nil
	}

	return RSASSA_PSS_SHA_512, SignatureAlgoNotSupportedError{alg: alg}
}

func convertToMap(i interface{}) (map[string]interface{}, error) {
	s, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(s, &m); err != nil {
		return nil, err
	}

	return m, nil
}

func mergeMaps(maps ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
