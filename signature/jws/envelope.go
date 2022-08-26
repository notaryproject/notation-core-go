package jws

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

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
	// check signer type
	var (
		method signingMethod
		err    error
	)
	if localSigner, ok := req.Signer.(signature.LocalSigner); ok {
		// for local signer
		method, err = newLocalSigningMethod(localSigner)
	} else {
		// for remote signer
		method, err = newRemoteSigningMethod(req.Signer)
	}
	if err != nil {
		return nil, &signature.MalformedSignRequestError{Msg: err.Error()}
	}

	// get all attributes ready to be signed
	signedAttrs, err := getSignedAttrs(req, method.Alg())
	if err != nil {
		return nil, err
	}

	// JWT sign and get certificate chain
	compact, certs, err := sign(req.Payload.Content, signedAttrs, method)
	if err != nil {
		return nil, &signature.MalformedSignRequestError{Msg: err.Error()}
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

// Verify checks the validity of the envelope and returns the payload and signerInfo
func (e *envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	if e.internalEnvelope == nil {
		return nil, nil, &signature.SignatureNotFoundError{}
	}

	if len(e.internalEnvelope.Header.CertChain) == 0 {
		return nil, nil, &signature.MalformedSignatureError{Msg: "certificate chain is not set"}
	}

	cert, err := x509.ParseCertificate(e.internalEnvelope.Header.CertChain[0])
	if err != nil {
		return nil, nil, &signature.MalformedSignatureError{Msg: "malformed leaf certificate"}
	}

	// verify JWT
	compact := compactJWS(e.internalEnvelope)
	if err = verifyJWT(compact, cert.PublicKey); err != nil {
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
		return nil, &signature.SignatureNotFoundError{}
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
		return nil, &signature.MalformedSignatureError{Msg: err.Error()}
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
		return nil, &signature.MalformedSignatureError{Msg: "cose envelope missing signature"}
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

// sign the given payload and headers using the given signature provider
func sign(payload jwtPayload, headers map[string]interface{}, method signingMethod) (string, []*x509.Certificate, error) {
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
