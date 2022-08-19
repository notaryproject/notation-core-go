package jws

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
)

// MediaTypeEnvelope defines the media type name of JWS envelope
const MediaTypeEnvelope = "application/jose+json"

func init() {
	if err := signature.RegisterEnvelopeType(MediaTypeEnvelope, NewEnvelope, ParseEnvelope); err != nil {
		panic(err)
	}
}

type envelope struct {
	internalEnvelope *jwsEnvelope
}

// NewEnvelope generates an JWS envelope
func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{},
	}
}

// ParseEnvelope parses the envelope bytes and return a JWS envelope
func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	var e jwsEnvelope
	err := json.Unmarshal(envelopeBytes, &e)
	if err != nil {
		return nil, &signature.MalformedSignatureError{Msg: err.Error()}
	}
	return &base.Envelope{
		Envelope: &envelope{internalEnvelope: &e},
		Raw:      envelopeBytes,
	}, nil
}

// Sign signs the envelope and return the encoded message
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	// get all attributes ready to be signed
	signedAttrs, err := getSignedAttrs(req)
	if err != nil {
		return nil, err
	}

	// JWT sign
	compact, err := sign(req.Payload.Content, signedAttrs, req.Signer)
	if err != nil {
		return nil, &signature.MalformedSignRequestError{Msg: err.Error()}
	}

	// get certificate chain
	certs, err := req.Signer.CertificateChain()
	if err != nil {
		return nil, err
	}

	// generate envelope
	env, err := generateJWS(compact, req, certs)
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(env)
	if err != nil {
		return nil, &signature.MalformedSignatureError{Msg: err.Error()}
	}
	e.internalEnvelope = env
	return encoded, nil
}

// compactJWS converts Flattened JWS JSON Serialization Syntax (section-7.2.2) to
// JWS Compact Serialization (section-7.1)
//
// [RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515.html
func compactJWS(envelope *jwsEnvelope) string {
	return strings.Join([]string{
		envelope.Protected,
		envelope.Payload,
		envelope.Signature}, ".")
}

// Verify checks the validity of the envelope and returns the payload and signerInfo
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
	compact := compactJWS(e.internalEnvelope)
	if err = verifyJWT(compact, cert); err != nil {
		return nil, nil, err
	}

	// extract payload
	payload, err := e.Payload()
	if err != nil {
		return nil, nil, err
	}

	// extract signer info
	signerInfo, err := e.SignerInfo()
	if err != nil {
		return nil, nil, err
	}
	return payload, signerInfo, nil
}

// Payload returns the payload of JWS envelope
func (e *envelope) Payload() (*signature.Payload, error) {
	if e.internalEnvelope == nil {
		return nil, &signature.MalformedSignatureError{Msg: "missing jws signature envelope"}
	}
	// parse protected header to get payload context type
	protected, err := parseProtectedHeaders(e.internalEnvelope.Protected)
	if err != nil {
		return nil, err
	}

	// convert JWS to JWT
	tokenString := compactJWS(e.internalEnvelope)

	// parse JWT to get payload context
	parser := jwt.NewParser(
		jwt.WithValidMethods(validMethods),
		jwt.WithJSONNumber(),
		jwt.WithoutClaimsValidation(),
	)
	var claims jwtPayload
	_, _, err = parser.ParseUnverified(tokenString, &claims)
	if err != nil {
		return nil, err
	}

	return &signature.Payload{
		Content:     claims,
		ContentType: protected.ContentType,
	}, nil
}

// SignerInfo returns the SignerInfo of JWS envelope
func (e *envelope) SignerInfo() (*signature.SignerInfo, error) {
	if e.internalEnvelope == nil {
		return nil, &signature.SignatureNotFoundError{}
	}
	var signInfo signature.SignerInfo

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
	if len(sig) == 0 {
		return nil, &signature.MalformedSignatureError{Msg: "cose envelope missing signature"}
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
	signInfo.UnsignedAttributes.TimestampSignature = e.internalEnvelope.Header.TimestampSignature

	return &signInfo, nil
}

// sign the given payload and headers using the given signing method and signature provider
func sign(payload jwtPayload, headers map[string]interface{}, signer signature.Signer) (string, error) {
	var privateKey interface{}
	var signingMethod jwt.SigningMethod
	if localSigner, ok := signer.(signature.LocalSigner); ok {
		// local signer
		alg, err := extractJwtAlgorithm(localSigner)
		if err != nil {
			return "", err
		}
		signingMethod = jwt.GetSigningMethod(alg)

		// sign with private key
		privateKey = localSigner.PrivateKey()
	} else {
		// remote signer
		signingMethod = newRemoteSigningMethod(signer)
	}
	// generate token
	token := jwt.NewWithClaims(signingMethod, payload)
	token.Header = headers

	return token.SignedString(privateKey)
}
