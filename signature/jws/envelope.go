// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jws

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	base *jwsEnvelope
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
		Envelope: &envelope{base: &e},
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
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
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
	var timestampErr *signature.TimestampError
	env, err := generateJWS(compact, req, signedAttrs[headerKeySigningScheme].(signature.SigningScheme), certs)
	// ignore any timestamping error, because it SHOULD not block the
	// signing process
	if err != nil && !errors.As(err, &timestampErr) {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	encoded, err := json.Marshal(env)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	e.base = env

	if timestampErr != nil {
		return encoded, timestampErr
	}
	return encoded, nil
}

// Verify verifies the envelope and returns its enclosed payload and signer info.
func (e *envelope) Verify() (*signature.EnvelopeContent, error) {
	if e.base == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}

	if len(e.base.Header.CertChain) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "certificate chain is not present"}
	}

	cert, err := x509.ParseCertificate(e.base.Header.CertChain[0])
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: "malformed leaf certificate"}
	}

	// verify JWT
	compact := compactJWS(e.base)
	if err = verifyJWT(compact, cert.PublicKey); err != nil {
		return nil, err
	}

	return e.Content()
}

// Content returns the payload and signer information of the envelope.
// Content is trusted only after the successful call to `Verify()`.
func (e *envelope) Content() (*signature.EnvelopeContent, error) {
	if e.base == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}

	// parse protected headers
	protected, err := parseProtectedHeaders(e.base.Protected)
	if err != nil {
		return nil, err
	}

	// extract payload
	payload, err := e.payload(protected)
	if err != nil {
		return nil, err
	}

	// extract signer info
	signerInfo, err := e.signerInfo(protected)
	if err != nil {
		return nil, err
	}
	return &signature.EnvelopeContent{
		SignerInfo: *signerInfo,
		Payload:    *payload,
	}, nil
}

// payload returns the payload of JWS envelope.
func (e *envelope) payload(protected *jwsProtectedHeader) (*signature.Payload, error) {
	payload, err := base64.RawURLEncoding.DecodeString(e.base.Payload)
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
func (e *envelope) signerInfo(protected *jwsProtectedHeader) (*signature.SignerInfo, error) {
	var signerInfo signature.SignerInfo

	// populate protected header to signerInfo
	if err := populateProtectedHeaders(protected, &signerInfo); err != nil {
		return nil, err
	}

	// parse signature
	sig, err := base64.RawURLEncoding.DecodeString(e.base.Signature)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	if len(sig) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "signature missing in jws-json envelope"}
	}
	signerInfo.Signature = sig

	// parse headers
	var certs []*x509.Certificate
	for _, certBytes := range e.base.Header.CertChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, &signature.InvalidSignatureError{Msg: err.Error()}
		}
		certs = append(certs, cert)
	}
	signerInfo.CertificateChain = certs
	signerInfo.UnsignedAttributes.SigningAgent = e.base.Header.SigningAgent
	signerInfo.UnsignedAttributes.TimestampSignature = e.base.Header.TimestampSignature
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
