package jws

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
)

// MediaTypeEnvelope defines the media type name of JWS envelope.
const MediaTypeEnvelope = "application/jose+json"

func init() {
	if err := signature.RegisterEnvelopeType(MediaTypeEnvelope, NewEnvelope, ParseEnvelope); err != nil {
		panic(err)
	}
}

type envelope struct {
	internalEnvelope *jwsEnvelope
}

// NewEnvelope generates an JWS envelope.
func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{},
	}
}

// ParseEnvelope parses the envelope bytes and return a JWS envelope.
func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	var e jwsEnvelope
	err := json.Unmarshal(envelopeBytes, &e)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	return &base.Envelope{
		Envelope: &envelope{internalEnvelope: &e},
		Raw:      envelopeBytes,
	}, nil
}

// Sign generates and sign the envelope according to the sign request.
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	// get signingMethod for JWT package
	method, err := getSigningMethod(req.Signer)
	if err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// get all attributes ready to be signed
	signedAttrs, err := getSignedAttributes(req, method.Alg())
	if err != nil {
		return nil, err
	}

	// parse payload as jwt.MapClaims
	// [jwt-go]: https://pkg.go.dev/github.com/dgrijalva/jwt-go#MapClaims
	var payload jwt.MapClaims
	if err = json.Unmarshal(req.Payload.Content, &payload); err != nil {
		return nil, &signature.InvalidSignRequestError{
			Msg: fmt.Sprintf("payload format error: %v", err.Error())}
	}

	// JWT sign and get certificate chain
	compact, certs, err := sign(payload, signedAttrs, method)
	if err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// generate envelope
	env, err := generateJWS(compact, req, certs)
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(env)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	e.internalEnvelope = env
	return encoded, nil
}

// Verify verifies the envelope and returns its enclosed payload and signer info.
func (e *envelope) Verify() (*signature.EnvelopeContent, error) {
	if e.internalEnvelope == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}

	if len(e.internalEnvelope.Header.CertChain) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "certificate chain is not set"}
	}

	cert, err := x509.ParseCertificate(e.internalEnvelope.Header.CertChain[0])
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: "malformed leaf certificate"}
	}

	// verify JWT
	compact := compactJWS(e.internalEnvelope)
	if err = verifyJWT(compact, cert.PublicKey); err != nil {
		return nil, err
	}

	return e.Content()
}

// Content returns the payload and signer information of the envelope.
// Content is trusted only after the successful call to `Verify()`.
func (e *envelope) Content() (*signature.EnvelopeContent, error) {
	// extract payload
	payload, err := e.payload()
	if err != nil {
		return nil, err
	}

	// extract signer info
	signerInfo, err := e.signerInfo()
	if err != nil {
		return nil, err
	}
	return &signature.EnvelopeContent{
		SignerInfo: *signerInfo,
		Payload:    *payload,
	}, nil
}

// payload returns the payload of JWS envelope.
func (e *envelope) payload() (*signature.Payload, error) {
	if e.internalEnvelope == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}
	// parse protected header to get payload context type
	protected, err := parseProtectedHeaders(e.internalEnvelope.Protected)
	if err != nil {
		return nil, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(e.internalEnvelope.Payload)
	if err != nil {
		return nil, &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("payload error: %v", err)}
	}

	return &signature.Payload{
		Content:     payload,
		ContentType: protected.ContentType,
	}, nil
}

// signerInfo returns the SignerInfo of JWS envelope.
func (e *envelope) signerInfo() (*signature.SignerInfo, error) {
	if e.internalEnvelope == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}
	var signerInfo signature.SignerInfo

	// parse protected headers
	protected, err := parseProtectedHeaders(e.internalEnvelope.Protected)
	if err != nil {
		return nil, err
	}
	if err := populateProtectedHeaders(protected, &signerInfo); err != nil {
		return nil, err
	}

	// parse signature
	sig, err := base64.RawURLEncoding.DecodeString(e.internalEnvelope.Signature)
	if err != nil {
		return nil, err
	}
	if len(sig) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "cose envelope missing signature"}
	}
	signerInfo.Signature = sig

	// parse headers
	var certs []*x509.Certificate
	for _, certBytes := range e.internalEnvelope.Header.CertChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	signerInfo.CertificateChain = certs
	signerInfo.UnsignedAttributes.SigningAgent = e.internalEnvelope.Header.SigningAgent
	signerInfo.UnsignedAttributes.TimestampSignature = e.internalEnvelope.Header.TimestampSignature
	return &signerInfo, nil
}

// sign the given payload and headers using the given signature provider.
func sign(payload jwt.MapClaims, headers map[string]interface{}, method signingMethod) (string, []*x509.Certificate, error) {
	// generate token
	token := jwt.NewWithClaims(method, payload)
	token.Header = headers

	// sign and return compact JWS
	compact, err := token.SignedString(method.PrivateKey())
	if err != nil {
		return "", nil, err
	}

	// access certificate chain after sign
	certs, err := method.CertificateChain()
	if err != nil {
		return "", nil, err
	}
	return compact, certs, nil
}
