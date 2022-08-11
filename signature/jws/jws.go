package jws

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
	nx509 "github.com/notaryproject/notation-core-go/x509"
)

const MediaTypeEnvelope = "application/jose+json"

func init() {
	if err := signature.RegisterEnvelopeType(MediaTypeEnvelope, NewEnvelope, ParseEnvelope); err != nil {
		panic(err)
	}
}

type envelope struct {
	internalEnvelope *JwsEnvelope
}

func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{},
	}
}

func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	var e JwsEnvelope
	err := json.Unmarshal(envelopeBytes, &e)
	if err != nil {
		return nil, err
	}
	return &base.Envelope{
		Envelope: &envelope{internalEnvelope: &e},
		Raw:      envelopeBytes,
	}, nil
}

func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	signer := req.Signer
	// if signer is LocalSigner, use build in jws signer
	if localSigner, ok := req.Signer.(signature.LocalSigner); ok {
		signer = &JwsSigner{LocalSigner: localSigner}
	}
	errorFunc := func(s string) error {
		return &signature.MalformedSignRequestError{Msg: s}
	}

	ks, err := req.Signer.KeySpec()
	if err != nil {
		return nil, errorFunc(err.Error())
	}
	alg := ks.SignatureAlgorithm()

	signedAttrs, err := getSignedAttrs(req, alg)
	if err != nil {
		return nil, err
	}

	compact, certs, err := sign(req.Payload.Content, signedAttrs, signer)
	if err != nil {
		return nil, errorFunc(err.Error())
	}

	// not performed by SignatureEnvelope's Sign function as we don't have access to certificates.
	if err := validateCertificateChain(certs, req.SigningTime, alg, errorFunc); err != nil {
		return nil, err
	}

	e.internalEnvelope, err = generateJws(compact, req, certs)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(e.internalEnvelope)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (e *envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	if e.internalEnvelope == nil {
		return nil, nil, &signature.SignatureNotFoundError{}
	}

	if len(e.internalEnvelope.Header.CertChain) == 0 {
		return nil, nil, &signature.MalformedSignatureError{Msg: "malformed leaf certificate"}
	}

	cert, err := x509.ParseCertificate(e.internalEnvelope.Header.CertChain[0])
	if err != nil {
		return nil, nil, &signature.MalformedSignatureError{Msg: "malformed leaf certificate"}
	}

	// verify JWT
	compact := strings.Join([]string{
		e.internalEnvelope.Protected,
		e.internalEnvelope.Payload,
		e.internalEnvelope.Signature}, ".")
	err = verifyJWT(compact, cert.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	// parse payload
	payloadContent, err := base64.RawURLEncoding.DecodeString(e.internalEnvelope.Payload)
	if err != nil {
		return nil, nil, err
	}
	signerInfo, err := e.SignerInfo()
	if err != nil {
		return nil, nil, err
	}
	return &signature.Payload{
		Content:     payloadContent,
		ContentType: signature.MediaTypePayloadV1}, signerInfo, nil
}

func (e *envelope) Payload() (*signature.Payload, error) {
	if e.internalEnvelope == nil {
		return nil, &signature.MalformedSignatureError{Msg: "missing jws signature envelope"}
	}
	if len(e.internalEnvelope.Payload) == 0 {
		return nil, &signature.MalformedSignatureError{Msg: "missing payload"}
	}
	protected, err := parseProtectedHeaders(e.internalEnvelope.Protected)
	if err != nil {
		return nil, err
	}
	if protected.ContentType != signature.MediaTypePayloadV1 {
		return nil, &signature.MalformedSignatureError{
			Msg: "content type requires application/vnd.cncf.notary.payload.v1+json, but got " + protected.ContentType}
	}
	return &signature.Payload{
		Content:     []byte(e.internalEnvelope.Payload),
		ContentType: protected.ContentType,
	}, nil
}

func (e *envelope) SignerInfo() (*signature.SignerInfo, error) {
	signInfo := signature.SignerInfo{}
	if e.internalEnvelope == nil {
		return nil, &signature.SignatureNotFoundError{}
	}

	// parse protected headers
	protected, err := parseProtectedHeaders(e.internalEnvelope.Protected)
	if err != nil {
		return nil, err
	}
	if err := populateProtectedHeaders(protected, &signInfo); err != nil {
		return nil, err
	}

	// parse signature
	sig, err := base64.RawURLEncoding.DecodeString(e.internalEnvelope.Signature)
	if err != nil {
		return nil, err
	}
	signInfo.Signature = sig

	// parse headers
	var certs []*x509.Certificate
	for _, certBytes := range e.internalEnvelope.Header.CertChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	signInfo.CertificateChain = certs
	signInfo.UnsignedAttributes.SigningAgent = e.internalEnvelope.Header.SigningAgent
	signInfo.TimestampSignature = e.internalEnvelope.Header.TimestampSignature

	return &signInfo, nil
}

// sign the given payload and headers using the given signing method and signature provider
func sign(payload []byte, headers map[string]interface{}, signer signature.Signer) (string, []*x509.Certificate, error) {
	jsonPHeaders, err := json.Marshal(headers)
	if err != nil {
		return "", nil, fmt.Errorf("failed to encode protected headers: %v", err)
	}
	protectedRaw := base64.RawURLEncoding.EncodeToString(jsonPHeaders)
	payloadRaw := base64.RawURLEncoding.EncodeToString(payload)
	digest := protectedRaw + "." + payloadRaw

	// check external or internal signer

	sigB, err := signer.Sign([]byte(digest))
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign digest. error : %v", err)
	}
	finalSig := digest + "." + base64.RawURLEncoding.EncodeToString(sigB)

	certs, err := signer.CertificateChain()
	if err != nil {
		return "", nil, err
	}
	return finalSig, certs, err
}

func validateCertificateChain(certChain []*x509.Certificate, signingTime time.Time, expectedAlg signature.Algorithm, f func(string) error) error {
	if len(certChain) == 0 {
		return f("certificate-chain not present or is empty")
	}

	err := nx509.ValidateCodeSigningCertChain(certChain, signingTime)
	if err != nil {
		return f(fmt.Sprintf("certificate-chain is invalid, %s", err))
	}

	keySpec, err := signature.ExtractKeySpec(certChain[0])
	if err != nil {
		return f(err.Error())
	}
	resSignAlgo := keySpec.SignatureAlgorithm()
	if resSignAlgo != expectedAlg {
		return f("mismatch between signature algorithm derived from signing certificate and signing algorithm specified")
	}

	return nil
}

func generateJws(compact string, req *signature.SignRequest, certs []*x509.Certificate) (*JwsEnvelope, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		// this should never happen
		return nil, errors.New("unexpected error occurred while generating a JWS-JSON serialization from compact serialization")
	}

	rawCerts := make([][]byte, len(certs))
	for i, cert := range certs {
		rawCerts[i] = cert.Raw
	}

	return &JwsEnvelope{
		Protected: parts[0],
		Payload:   parts[1],
		Signature: parts[2],
		Header: jwsUnprotectedHeader{
			CertChain:    rawCerts,
			SigningAgent: req.SigningAgent,
		},
	}, nil
}

// verifyJWT verifies the JWT token against the specified verification key
func verifyJWT(tokenString string, key crypto.PublicKey) error {
	signingMethod, err := getSigningMethod(key)
	if err != nil {
		return err
	}

	// parse and verify token
	parser := &jwt.Parser{
		ValidMethods:         []string{"PS256", "PS384", "PS512", "ES256", "ES384", "ES512"},
		UseJSONNumber:        true,
		SkipClaimsValidation: true,
	}

	if _, err := parser.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != signingMethod.Alg() {
			return nil, &signature.MalformedSignatureError{
				Msg: fmt.Sprintf("unexpected signing method: %v: require %v", t.Method.Alg(), signingMethod.Alg())}
		}

		// override default signing method with key-specific method
		t.Method = signingMethod
		return key, nil
	}); err != nil {
		return &signature.SignatureIntegrityError{Err: err}
	}
	return nil
}

func parseProtectedHeaders(encoded string) (*jwsProtectedHeader, error) {
	rawProtected, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, &signature.MalformedSignatureError{
			Msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}

	// To Unmarshal JSON with some known(jwsProtectedHeader), and some unknown(jwsProtectedHeader.ExtendedAttributes) field names.
	// We unmarshal twice: once into a value of type jwsProtectedHeader and once into a value of type jwsProtectedHeader.ExtendedAttributes(map[string]interface{})
	// and removing the keys are already been defined in jwsProtectedHeader.
	var protected jwsProtectedHeader
	if err = json.Unmarshal(rawProtected, &protected); err != nil {
		return nil, &signature.MalformedSignatureError{
			Msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}
	if err = json.Unmarshal(rawProtected, &protected.ExtendedAttributes); err != nil {
		return nil, &signature.MalformedSignatureError{
			Msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}

	// delete attributes that are already defined in jwsProtectedHeader.
	delete(protected.ExtendedAttributes, headerKeyAlg)
	delete(protected.ExtendedAttributes, headerKeyCty)
	delete(protected.ExtendedAttributes, headerKeyCrit)
	delete(protected.ExtendedAttributes, headerKeySigningTime)
	delete(protected.ExtendedAttributes, headerKeyExpiry)

	return &protected, nil
}

func populateProtectedHeaders(protectedHdr *jwsProtectedHeader, signInfo *signature.SignerInfo) error {
	err := validateCriticalHeaders(protectedHdr)
	if err != nil {
		return err
	}

	if signInfo.SignatureAlgorithm, err = getSignatureAlgo(protectedHdr.Algorithm); err != nil {
		return err
	}

	// signInfo.Payload.ContentType = protectedHdr.ContentType
	signInfo.SignedAttributes.SigningTime = protectedHdr.SigningTime.Truncate(time.Second)
	if protectedHdr.Expiry != nil {
		signInfo.SignedAttributes.Expiry = protectedHdr.Expiry.Truncate(time.Second)
	}
	signInfo.SignedAttributes.ExtendedAttributes = getExtendedAttributes(protectedHdr.ExtendedAttributes, protectedHdr.Critical)
	return nil
}

func validateCriticalHeaders(protectedHdr *jwsProtectedHeader) error {
	mustMarkedCrit := map[string]bool{}
	if protectedHdr.Expiry != nil && !protectedHdr.Expiry.IsZero() {
		mustMarkedCrit[headerKeyExpiry] = true
	}

	for _, val := range protectedHdr.Critical {
		if _, ok := mustMarkedCrit[val]; ok {
			delete(mustMarkedCrit, val)
		} else {
			if _, ok := protectedHdr.ExtendedAttributes[val]; !ok {
				return &signature.MalformedSignatureError{
					Msg: fmt.Sprintf("%q header is marked critical but not present", val)}
			}
		}
	}

	// validate all required critical headers are present.
	if len(mustMarkedCrit) != 0 {
		// This is not taken care by VerifySignerInfo method
		return &signature.MalformedSignatureError{Msg: "required headers not marked critical"}
	}

	return nil
}

func getSignatureAlgo(alg string) (signature.Algorithm, error) {
	signatureAlg, ok := jwsAlgSignatureAlgMap[alg]
	if !ok {
		return 0, &signature.SignatureAlgoNotSupportedError{Alg: alg}
	}

	return signatureAlg, nil
}

func getExtendedAttributes(attrs map[string]interface{}, critical []string) []signature.Attribute {
	extendedAttr := make([]signature.Attribute, 0, len(attrs))
	for key, value := range attrs {
		extendedAttr = append(extendedAttr, signature.Attribute{
			Key:      key,
			Critical: contains(critical, key),
			Value:    value,
		})
	}
	return extendedAttr
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
