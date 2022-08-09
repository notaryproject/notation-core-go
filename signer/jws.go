package signer

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MediaTypeJWSJson SignatureMediaType = "application/jose+json"
)

const (
	headerKeyExpiry                       = "io.cncf.notary.expiry"
	headerKeySigningTime                  = "io.cncf.notary.signingTime"
	headerKeyAuthenticSigningTime         = "io.cncf.notary.authenticSigningTime"
	headerKeySigningScheme                = "io.cncf.notary.signingScheme"
	headerKeyVerificationPlugin           = "io.cncf.notary.verificationPlugin"
	headerKeyVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
	headerKeyCrit                         = "crit"
	headerKeyAlg                          = "alg"
	headerKeyCty                          = "cty"
)

var signatureAlgJWSAlgMap = map[SignatureAlgorithm]string{
	RSASSA_PSS_SHA_256: "PS256",
	RSASSA_PSS_SHA_384: "PS384",
	RSASSA_PSS_SHA_512: "PS512",
	ECDSA_SHA_256:      "ES256",
	ECDSA_SHA_384:      "ES384",
	ECDSA_SHA_512:      "ES512",
}

var jwsAlgSignatureAlgMap = reverseMap(signatureAlgJWSAlgMap)

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
	errorFunc := func(s string) error {
		return MalformedSignRequestError{msg: s}
	}

	ks, err := req.SignatureProvider.KeySpec()
	if err != nil {
		return nil, errorFunc(err.Error())
	}
	alg := ks.SignatureAlgorithm()

	signedAttrs, err := getSignedAttrs(req, alg)
	if err != nil {
		return nil, err
	}

	compact, certs, err := sign(req.Payload, signedAttrs, req.SignatureProvider)
	if err != nil {
		return nil, errorFunc(err.Error())
	}

	// not performed by SignatureEnvelope's Sign function as we don't have access to certificates.
	if err := validateCertificateChain(certs, req.SigningTime, alg, errorFunc); err != nil {
		return nil, err
	}

	j, err := generateJws(compact, req, certs)
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

	// To Unmarshal JSON with some known(jwsProtectedHeader), and some unknown(jwsProtectedHeader.ExtendedAttributes) field names.
	// We unmarshal twice: once into a value of type jwsProtectedHeader and once into a value of type jwsProtectedHeader.ExtendedAttributes(map[string]interface{})
	// and removing the keys are already been defined in jwsProtectedHeader.
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
	delete(protected.ExtendedAttributes, headerKeyAuthenticSigningTime)
	delete(protected.ExtendedAttributes, headerKeySigningScheme)
	delete(protected.ExtendedAttributes, headerKeyVerificationPlugin)
	delete(protected.ExtendedAttributes, headerKeyVerificationPluginMinVersion)

	return &protected, nil
}

func populateProtectedHeaders(protectedHdr *jwsProtectedHeader, signInfo *SignerInfo) error {
	err := validateProtectedHeaders(protectedHdr)
	if err != nil {
		return err
	}

	if signInfo.SignatureAlgorithm, err = getSignatureAlgo(protectedHdr.Algorithm); err != nil {
		return err
	}

	signInfo.PayloadContentType = protectedHdr.ContentType
	signInfo.SignedAttributes.ExtendedAttributes = getExtendedAttributes(protectedHdr.ExtendedAttributes, protectedHdr.Critical)
	signInfo.SigningScheme = protectedHdr.SigningScheme
	signInfo.SignedAttributes.VerificationPlugin = protectedHdr.VerificationPlugin
	signInfo.SignedAttributes.VerificationPluginMinVersion = protectedHdr.VerificationPluginMinVersion
	if protectedHdr.Expiry != nil {
		signInfo.SignedAttributes.Expiry = *protectedHdr.Expiry
	}
	switch protectedHdr.SigningScheme {
	case SigningSchemeX509:
		if protectedHdr.SigningTime != nil {
			signInfo.SignedAttributes.SigningTime = *protectedHdr.SigningTime
		}
	case SigningSchemeX509SigningAuthority:
		if protectedHdr.AuthenticSigningTime != nil {
			signInfo.SignedAttributes.SigningTime = *protectedHdr.AuthenticSigningTime
		}
	}
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

func validateProtectedHeaders(protectedHdr *jwsProtectedHeader) error {
	// validate headers that should not be present as per signing schemes
	switch protectedHdr.SigningScheme {
	case SigningSchemeX509:
		if protectedHdr.AuthenticSigningTime != nil {
			return MalformedSignatureError{msg: fmt.Sprintf("%q header must not be present for %s signing scheme", headerKeyAuthenticSigningTime, SigningSchemeX509)}
		}
	case SigningSchemeX509SigningAuthority:
		if protectedHdr.SigningTime != nil {
			return MalformedSignatureError{msg: fmt.Sprintf("%q header must not be present for %s signing scheme", headerKeySigningTime, SigningSchemeX509SigningAuthority)}
		}
		if protectedHdr.AuthenticSigningTime == nil {
			return MalformedSignatureError{msg: fmt.Sprintf("%q header must be present for %s signing scheme", headerKeyAuthenticSigningTime, SigningSchemeX509)}
		}
	}

	return validateCriticalHeaders(protectedHdr)
}

// validateCriticalHeaders validates headers that should be present or marked critical as per singing scheme
func validateCriticalHeaders(protectedHdr *jwsProtectedHeader) error {
	if len(protectedHdr.Critical) == 0 {
		return MalformedSignatureError{"missing `crit` header"}
	}

	mustMarkedCrit := map[string]bool{headerKeySigningScheme: true}
	if protectedHdr.Expiry != nil && !protectedHdr.Expiry.IsZero() {
		mustMarkedCrit[headerKeyExpiry] = true
	}

	if protectedHdr.SigningScheme == SigningSchemeX509SigningAuthority {
		mustMarkedCrit[headerKeyAuthenticSigningTime] = true
	}

	if protectedHdr.VerificationPlugin != "" {
		mustMarkedCrit[headerKeyVerificationPlugin] = true
	}

	if protectedHdr.VerificationPluginMinVersion != "" {
		mustMarkedCrit[headerKeyVerificationPluginMinVersion] = true
	}

	for _, val := range protectedHdr.Critical {
		if _, ok := mustMarkedCrit[val]; ok {
			delete(mustMarkedCrit, val)
		} else {
			if _, ok := protectedHdr.ExtendedAttributes[val]; !ok {
				return MalformedSignatureError{msg: fmt.Sprintf("%q header is marked critical but not present", val)}
			}
		}
	}

	// validate all required critical headers are present.
	if len(mustMarkedCrit) != 0 {
		// This is not taken care by VerifySignerInfo method
		keys := make([]string, 0, len(mustMarkedCrit))
		for k := range mustMarkedCrit {
			keys = append(keys, k)
		}
		return MalformedSignatureError{fmt.Sprintf("these required headers are not marked as critical: %v", keys)}
	}

	return nil
}

func getSignedAttrs(req SignRequest, sigAlg SignatureAlgorithm) (map[string]interface{}, error) {
	extAttrs := make(map[string]interface{})
	crit := []string{headerKeySigningScheme}

	for _, elm := range req.ExtendedSignedAttrs {
		extAttrs[elm.Key] = elm.Value
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
	}

	alg, err := getJWSAlgo(sigAlg)
	if err != nil {
		return nil, err
	}

	jwsProtectedHdr := jwsProtectedHeader{
		Algorithm:     alg,
		ContentType:   req.PayloadContentType,
		SigningScheme: req.SigningScheme,
	}

	switch req.SigningScheme {
	case SigningSchemeX509:
		jwsProtectedHdr.SigningTime = &req.SigningTime
	case SigningSchemeX509SigningAuthority:
		crit = append(crit, headerKeyAuthenticSigningTime)
		jwsProtectedHdr.AuthenticSigningTime = &req.SigningTime
	}

	if !req.Expiry.IsZero() {
		crit = append(crit, headerKeyExpiry)
		jwsProtectedHdr.Expiry = &req.Expiry
	}
	if strings.TrimSpace(req.VerificationPlugin) != "" {
		crit = append(crit, headerKeyVerificationPlugin)
		jwsProtectedHdr.VerificationPlugin = req.VerificationPlugin
	}
	if strings.TrimSpace(req.VerificationPluginMinVersion) != "" {
		crit = append(crit, headerKeyVerificationPluginMinVersion)
		jwsProtectedHdr.VerificationPluginMinVersion = req.VerificationPluginMinVersion
	}

	jwsProtectedHdr.Critical = crit
	m, err := convertToMap(jwsProtectedHdr)
	if err != nil {
		return nil, MalformedSignRequestError{msg: fmt.Sprintf("unexpected error occured while creating protected headers, Error: %s", err.Error())}
	}

	return mergeMaps(m, extAttrs), nil
}

// ***********************************************************************
// jwsEnvelope-JSON specific code
// ***********************************************************************

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
	ContentType PayloadContentType `json:"cty"`

	// Lists the headers that implementation MUST understand and process.
	Critical []string `json:"crit,omitempty"`

	// The "best by use" time for the artifact, as defined by the signer.
	Expiry *time.Time `json:"io.cncf.notary.expiry,omitempty"`

	// Specifies the Notary v2 Signing Scheme used by the signature.
	SigningScheme SigningScheme `json:"io.cncf.notary.signingScheme"`

	// The time at which the signature was generated. only valid when signing scheme is `notary.x509`
	SigningTime *time.Time `json:"io.cncf.notary.signingTime,omitempty"`

	// The time at which the signature was generated. only valid when signing scheme is `notary.x509.signingAuthority`
	AuthenticSigningTime *time.Time `json:"io.cncf.notary.authenticSigningTime,omitempty"`

	// VerificationPlugin specifies the name of the verification plugin that should be used to verify the signature.
	VerificationPlugin string `json:"io.cncf.notary.verificationPlugin,omitempty"`

	// VerificationPluginMinVersion specifies the minimum version of the verification plugin that should be used to verify the signature.
	VerificationPluginMinVersion string `json:"io.cncf.notary.verificationPluginMinVersion,omitempty"`

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

func generateJws(compact string, req SignRequest, certs []*x509.Certificate) (*jwsInternalEnvelope, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		// this should never happen
		return nil, errors.New("unexpected error occurred while generating a JWS-JSON serialization from compact serialization")
	}

	rawCerts := make([][]byte, len(certs))
	for i, cert := range certs {
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

// sign the given payload and headers using the given signing method and signature provider
func sign(payload []byte, headers map[string]interface{}, sigPro SignatureProvider) (string, []*x509.Certificate, error) {
	jsonPHeaders, err := json.Marshal(headers)
	if err != nil {
		return "", nil, fmt.Errorf("failed to encode protected headers: %v", err)
	}
	protectedRaw := base64.RawURLEncoding.EncodeToString(jsonPHeaders)
	payloadRaw := base64.RawURLEncoding.EncodeToString(payload)
	signingString := protectedRaw + "." + payloadRaw

	sigB, certs, err := sigPro.Sign([]byte(signingString))
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign digest. error : %v", err)
	}
	finalSig := signingString + "." + base64.RawURLEncoding.EncodeToString(sigB)
	return finalSig, certs, err
}

func getSignatureAlgo(alg string) (SignatureAlgorithm, error) {
	signatureAlg, ok := jwsAlgSignatureAlgMap[alg]
	if !ok {
		return "", SignatureAlgoNotSupportedError{alg: alg}
	}

	return signatureAlg, nil
}

func getJWSAlgo(alg SignatureAlgorithm) (string, error) {
	jwsAlg, ok := signatureAlgJWSAlgMap[alg]
	if !ok {
		return "", SignatureAlgoNotSupportedError{alg: string(alg)}
	}

	return jwsAlg, nil
}

func reverseMap(m map[SignatureAlgorithm]string) map[string]SignatureAlgorithm {
	n := make(map[string]SignatureAlgorithm, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
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
