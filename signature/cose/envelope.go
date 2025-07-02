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

package cose

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/notaryproject/notation-core-go/internal/timestamp"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
	"github.com/notaryproject/tspclient-go"
	"github.com/veraison/go-cose"
)

// MediaTypeEnvelope is the COSE signature envelope blob mediaType.
const MediaTypeEnvelope = "application/cose"

var (
	// encMode is the encoding mode used in Sign
	encMode cbor.EncMode

	// decMode is the decoding mode used in Content
	decMode cbor.DecMode
)

func init() {
	err := signature.RegisterEnvelopeType(MediaTypeEnvelope, NewEnvelope, ParseEnvelope)
	if err != nil {
		panic(err)
	}

	encOpts := cbor.EncOptions{
		Time:    cbor.TimeUnix,
		TimeTag: cbor.EncTagRequired,
	}
	encMode, err = encOpts.EncMode()
	if err != nil {
		panic(err)
	}

	decOpts := cbor.DecOptions{
		TimeTag: cbor.DecTagRequired,
	}
	decMode, err = decOpts.DecMode()
	if err != nil {
		panic(err)
	}
}

// Protected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerLabelExpiry               = "io.cncf.notary.expiry"
	headerLabelSigningScheme        = "io.cncf.notary.signingScheme"
	headerLabelSigningTime          = "io.cncf.notary.signingTime"
	headerLabelAuthenticSigningTime = "io.cncf.notary.authenticSigningTime"
)

// Unprotected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerLabelTimestampSignature = "io.cncf.notary.timestampSignature"
	headerLabelSigningAgent       = "io.cncf.notary.signingAgent"
)

// Map of cose.Algorithm to signature.Algorithm
var coseAlgSignatureAlgMap = map[cose.Algorithm]signature.Algorithm{
	cose.AlgorithmPS256: signature.AlgorithmPS256,
	cose.AlgorithmPS384: signature.AlgorithmPS384,
	cose.AlgorithmPS512: signature.AlgorithmPS512,
	cose.AlgorithmES256: signature.AlgorithmES256,
	cose.AlgorithmES384: signature.AlgorithmES384,
	cose.AlgorithmES512: signature.AlgorithmES512,
}

// Map of signingScheme to signingTime header label
var signingSchemeTimeLabelMap = map[signature.SigningScheme]string{
	signature.SigningSchemeX509:                 headerLabelSigningTime,
	signature.SigningSchemeX509SigningAuthority: headerLabelAuthenticSigningTime,
}

// signer interface is a cose.Signer with certificate chain fetcher.
type signer interface {
	cose.Signer
	CertificateChain() []*x509.Certificate
}

// remoteSigner implements signer interface.
// It is used in Sign process when base's Sign implementation is desired.
type remoteSigner struct {
	base  signature.Signer
	alg   cose.Algorithm
	certs []*x509.Certificate
}

func newRemoteSigner(base signature.Signer) (*remoteSigner, error) {
	keySpec, err := base.KeySpec()
	if err != nil {
		return nil, err
	}
	alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return nil, err
	}
	return &remoteSigner{
		base: base,
		alg:  alg,
	}, nil
}

// Algorithm implements cose.Signer interface.
func (signer *remoteSigner) Algorithm() cose.Algorithm {
	return signer.alg
}

// Sign implements cose.Signer interface.
func (signer *remoteSigner) Sign(rand io.Reader, payload []byte) ([]byte, error) {
	signature, certs, err := signer.base.Sign(payload)
	if err != nil {
		return nil, err
	}
	signer.certs = certs
	return signature, nil
}

// CertificateChain implements signer interface.
func (signer *remoteSigner) CertificateChain() []*x509.Certificate {
	return signer.certs
}

type localSigner struct {
	cose.Signer
	certs []*x509.Certificate
}

func newLocalSigner(base signature.LocalSigner) (*localSigner, error) {
	key := base.PrivateKey()
	if cryptoSigner, ok := key.(crypto.Signer); ok {
		certs, err := base.CertificateChain()
		if err != nil {
			return nil, err
		}
		keySpec, err := base.KeySpec()
		if err != nil {
			return nil, err
		}
		alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
		if err != nil {
			return nil, err
		}
		coseSigner, err := cose.NewSigner(alg, cryptoSigner)
		if err != nil {
			return nil, err
		}
		return &localSigner{
			Signer: coseSigner,
			certs:  certs,
		}, nil
	}
	return nil, &signature.UnsupportedSigningKeyError{}
}

// CertificateChain implements signer interface.
func (signer *localSigner) CertificateChain() []*x509.Certificate {
	return signer.certs
}

type envelope struct {
	base *cose.Sign1Message
}

// NewEnvelope initializes an empty COSE signature envelope.
func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{},
	}
}

// ParseEnvelope parses envelopeBytes to a COSE signature envelope.
func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(envelopeBytes); err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	return &base.Envelope{
		Envelope: &envelope{
			base: &msg,
		},
		Raw: envelopeBytes,
	}, nil
}

// Sign implements signature.Envelope interface.
// On success, this function returns the COSE signature envelope byte slice.
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	// get built-in signer from go-cose or remote signer based on req.Signer
	signer, err := getSigner(req.Signer)
	if err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// prepare COSE_Sign1 message
	msg := cose.NewSign1Message()

	// generate protected headers of COSE envelope
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())
	if err := generateProtectedHeaders(req, msg.Headers.Protected); err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// generate payload of COSE envelope
	msg.Headers.Protected[cose.HeaderLabelContentType] = req.Payload.ContentType
	msg.Payload = req.Payload.Content

	// core sign process, generate signature of COSE envelope
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, &signature.InvalidSignRequestError{Msg: err.Error()}
	}

	// generate unprotected headers of COSE envelope.
	generateUnprotectedHeaders(req, signer, msg.Headers.Unprotected)

	// timestamping
	if req.SigningScheme == signature.SigningSchemeX509 && req.Timestamper != nil {
		hash, err := hashFromCOSEAlgorithm(signer.Algorithm())
		if err != nil {
			return nil, &signature.TimestampError{Detail: err}
		}
		timestampOpts := tspclient.RequestOptions{
			Content:       msg.Signature,
			HashAlgorithm: hash,
		}
		timestampToken, err := timestamp.Timestamp(req, timestampOpts)
		if err != nil {
			return nil, &signature.TimestampError{Detail: err}
		}
		// on success, embed the timestamp token to Unprotected header
		msg.Headers.Unprotected[headerLabelTimestampSignature] = timestampToken
	}

	// encode Sign1Message into COSE_Sign1_Tagged object
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	e.base = msg

	return encoded, nil
}

// Verify implements signature.Envelope interface.
// Note: Verfiy only verifies integrity of the given COSE envelope.
func (e *envelope) Verify() (*signature.EnvelopeContent, error) {
	// sanity check
	if e.base == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}

	certs, ok := e.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([]any)
	if !ok || len(certs) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "certificate chain is not present"}
	}
	certRaw, ok := certs[0].([]byte)
	if !ok {
		return nil, &signature.InvalidSignatureError{Msg: "COSE envelope malformed leaf certificate"}
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: "malformed leaf certificate"}
	}

	// core verify process, verify integrity of COSE envelope
	publicKeyAlg, err := getSignatureAlgorithm(cert)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	verifier, err := cose.NewVerifier(publicKeyAlg, cert.PublicKey)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}
	err = e.base.Verify(nil, verifier)
	if err != nil {
		return nil, &signature.SignatureIntegrityError{Err: err}
	}

	// extract content
	return e.Content()
}

// Content implements signature.Envelope interface.
func (e *envelope) Content() (*signature.EnvelopeContent, error) {
	// sanity check
	if e.base == nil {
		return nil, &signature.SignatureEnvelopeNotFoundError{}
	}

	payload, err := e.payload()
	if err != nil {
		return nil, err
	}
	signerInfo, err := e.signerInfo()
	if err != nil {
		return nil, err
	}
	return &signature.EnvelopeContent{
		SignerInfo: *signerInfo,
		Payload:    *payload,
	}, nil
}

// Given a COSE envelope, extracts its signature.Payload.
func (e *envelope) payload() (*signature.Payload, error) {
	cty, ok := e.base.Headers.Protected[cose.HeaderLabelContentType]
	if !ok {
		return nil, &signature.InvalidSignatureError{Msg: "missing content type"}
	}
	var contentType string
	if contentType, ok = cty.(string); !ok {
		return nil, &signature.InvalidSignatureError{Msg: "content type should be of 'tstr' type"}
	}
	return &signature.Payload{
		ContentType: contentType,
		Content:     e.base.Payload,
	}, nil
}

// Given a COSE envelope, extracts its signature.SignerInfo.
func (e *envelope) signerInfo() (*signature.SignerInfo, error) {
	var signerInfo signature.SignerInfo

	// parse signature of COSE envelope, populate signerInfo.Signature
	sig := e.base.Signature
	if len(sig) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "signature missing in COSE envelope"}
	}
	signerInfo.Signature = sig

	// parse protected headers of COSE envelope and populate related
	// signerInfo fields
	err := parseProtectedHeaders(e.base.Headers.RawProtected, e.base.Headers.Protected, &signerInfo)
	if err != nil {
		return nil, &signature.InvalidSignatureError{Msg: err.Error()}
	}

	// parse unprotected headers of COSE envelope
	certs, ok := e.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([]any)
	if !ok || len(certs) == 0 {
		return nil, &signature.InvalidSignatureError{Msg: "certificate chain is not present"}
	}
	var certChain []*x509.Certificate
	for _, c := range certs {
		certRaw, ok := c.([]byte)
		if !ok {
			return nil, &signature.InvalidSignatureError{Msg: "certificate chain is not present"}
		}
		cert, err := x509.ParseCertificate(certRaw)
		if err != nil {
			return nil, &signature.InvalidSignatureError{Msg: err.Error()}
		}
		certChain = append(certChain, cert)
	}
	// populate signerInfo.CertificateChain
	signerInfo.CertificateChain = certChain

	// populate signerInfo.UnsignedAttributes.SigningAgent
	if h, ok := e.base.Headers.Unprotected[headerLabelSigningAgent].(string); ok {
		signerInfo.UnsignedAttributes.SigningAgent = h
	}

	// populate signerInfo.UnsignedAttributes.TimestampSignature
	if timestamepToken, ok := e.base.Headers.Unprotected[headerLabelTimestampSignature].([]byte); ok {
		signerInfo.UnsignedAttributes.TimestampSignature = timestamepToken
	}

	return &signerInfo, nil
}

// getSignatureAlgorithm picks up a recommended signing algorithm for given
// certificate.
func getSignatureAlgorithm(signingCert *x509.Certificate) (cose.Algorithm, error) {
	keySpec, err := signature.ExtractKeySpec(signingCert)
	if err != nil {
		return 0, err
	}
	return getSignatureAlgorithmFromKeySpec(keySpec)
}

// getSignatureAlgorithmFromKeySpec ensures the signing algorithm satisfies
// algorithm requirements.
func getSignatureAlgorithmFromKeySpec(keySpec signature.KeySpec) (cose.Algorithm, error) {
	switch keySpec.Type {
	case signature.KeyTypeRSA:
		switch keySpec.Size {
		case 2048:
			return cose.AlgorithmPS256, nil
		case 3072:
			return cose.AlgorithmPS384, nil
		case 4096:
			return cose.AlgorithmPS512, nil
		default:
			return 0, &signature.UnsupportedSigningKeyError{Msg: fmt.Sprintf("RSA: key size %d not supported", keySpec.Size)}
		}
	case signature.KeyTypeEC:
		switch keySpec.Size {
		case 256:
			return cose.AlgorithmES256, nil
		case 384:
			return cose.AlgorithmES384, nil
		case 521:
			return cose.AlgorithmES512, nil
		default:
			return 0, &signature.UnsupportedSigningKeyError{Msg: fmt.Sprintf("EC: key size %d not supported", keySpec.Size)}
		}
	default:
		return 0, &signature.UnsupportedSigningKeyError{Msg: "key type not supported"}
	}
}

// getSigner returns the built-in implementation of cose.Signer from go-cose
// or a remote signer implementation of cose.Signer.
func getSigner(signer signature.Signer) (signer, error) {
	if localSigner, ok := signer.(signature.LocalSigner); ok {
		return newLocalSigner(localSigner)
	}
	return newRemoteSigner(signer)
}

// generateProtectedHeaders creates Protected Headers of the COSE envelope
// during Sign process.
func generateProtectedHeaders(req *signature.SignRequest, protected cose.ProtectedHeader) error {
	// signingScheme
	crit := []any{headerLabelSigningScheme}
	protected[headerLabelSigningScheme] = string(req.SigningScheme)

	// signingTime/authenticSigningTime
	signingTimeLabel, ok := signingSchemeTimeLabelMap[req.SigningScheme]
	if !ok {
		return &signature.InvalidSignRequestError{Msg: "signing scheme: require notary.x509 or notary.x509.signingAuthority"}
	}
	rawTimeCBOR, err := encodeTime(req.SigningTime)
	if err != nil {
		return &signature.InvalidSignRequestError{Msg: fmt.Sprintf("signing time: %q", err)}
	}
	protected[signingTimeLabel] = rawTimeCBOR
	if signingTimeLabel == headerLabelAuthenticSigningTime {
		crit = append(crit, headerLabelAuthenticSigningTime)
	}

	// expiry
	if !req.Expiry.IsZero() {
		crit = append(crit, headerLabelExpiry)
		rawExpiryCBOR, err := encodeTime(req.Expiry)
		if err != nil {
			return &signature.InvalidSignRequestError{Msg: fmt.Sprintf("expiry: %q", err)}
		}
		protected[headerLabelExpiry] = rawExpiryCBOR
	}

	// extended attributes
	for _, elm := range req.ExtendedSignedAttributes {
		if _, ok := protected[elm.Key]; ok {
			return &signature.InvalidSignRequestError{Msg: fmt.Sprintf("%q already exists in the protected header", elm.Key)}
		}
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
		protected[elm.Key] = elm.Value
	}

	// critical headers
	protected[cose.HeaderLabelCritical] = crit

	return nil
}

// generateUnprotectedHeaders creates Unprotected Headers of the COSE envelope
// during Sign process.
func generateUnprotectedHeaders(req *signature.SignRequest, signer signer, unprotected cose.UnprotectedHeader) {
	// signing agent
	if req.SigningAgent != "" {
		unprotected[headerLabelSigningAgent] = req.SigningAgent
	}

	// certChain
	certs := signer.CertificateChain()
	certChain := make([]any, len(certs))
	for i, c := range certs {
		certChain[i] = c.Raw
	}
	unprotected[cose.HeaderLabelX5Chain] = certChain
}

// parseProtectedHeaders parses COSE envelope's protected headers and
// populates signature.SignerInfo.
func parseProtectedHeaders(rawProtected cbor.RawMessage, protected cose.ProtectedHeader, signerInfo *signature.SignerInfo) error {
	// validate critical headers and return extendedAttributeKeys
	extendedAttributeKeys, err := validateCritHeaders(protected)
	if err != nil {
		return err
	}

	// populate signerInfo.SignatureAlgorithm
	alg, err := protected.Algorithm()
	if err != nil {
		return err
	}
	sigAlg, ok := coseAlgSignatureAlgMap[alg]
	if !ok {
		return &signature.InvalidSignatureError{Msg: "signature algorithm not supported: " + strconv.Itoa(int(alg))}
	}
	signerInfo.SignatureAlgorithm = sigAlg

	// populate signerInfo.SignedAttributes.SigningScheme
	// headerLabelSigningScheme header has already been checked by
	// validateCritHeaders() at the beginning of this function.
	signingSchemeString := protected[headerLabelSigningScheme].(string)
	signingScheme := signature.SigningScheme(signingSchemeString)
	signerInfo.SignedAttributes.SigningScheme = signingScheme
	signingTimeLabel, ok := signingSchemeTimeLabelMap[signingScheme]
	if !ok {
		return &signature.InvalidSignatureError{Msg: "unsupported signingScheme: " + signingSchemeString}
	}

	// parse CBOR map from raw protected header for tag validation
	headerMap, err := generateRawProtectedCBORMap(rawProtected)
	if err != nil {
		return &signature.InvalidSignatureError{Msg: "generateRawProtectedCBORMap failed: " + err.Error()}
	}

	// populate signerInfo.SignedAttributes.SigningTime
	signingTime, err := parseTime(headerMap, signingTimeLabel, protected)
	if err != nil {
		return &signature.InvalidSignatureError{Msg: fmt.Sprintf("invalid signingTime: %v", err)}
	}
	signerInfo.SignedAttributes.SigningTime = signingTime

	// populate signerInfo.SignedAttributes.Expiry
	if _, ok := protected[headerLabelExpiry]; ok {
		expiry, err := parseTime(headerMap, headerLabelExpiry, protected)
		if err != nil {
			return &signature.InvalidSignatureError{Msg: fmt.Sprintf("invalid expiry: %v", err)}
		}
		signerInfo.SignedAttributes.Expiry = expiry
	}

	// populate signerInfo.SignedAttributes.ExtendedAttributes
	signerInfo.SignedAttributes.ExtendedAttributes, err = generateExtendedAttributes(extendedAttributeKeys, protected)
	return err
}

// validateCritHeaders does a two-way check, namely:
// 1. validate that all critical headers are present in the protected bucket
// 2. validate that all required headers(as per spec) are marked critical
// Returns list of extended attribute keys
func validateCritHeaders(protected cose.ProtectedHeader) ([]any, error) {
	// This ensures all critical headers are present in the protected bucket.
	labels, err := protected.Critical()
	if err != nil {
		return nil, err
	}

	// set of headers that must be marked as crit
	mustMarkedCrit := make(map[any]struct{})
	mustMarkedCrit[headerLabelSigningScheme] = struct{}{}
	signingScheme, ok := protected[headerLabelSigningScheme].(string)
	if !ok {
		return nil, &signature.InvalidSignatureError{Msg: "invalid signingScheme"}
	}
	if signature.SigningScheme(signingScheme) == signature.SigningSchemeX509SigningAuthority {
		mustMarkedCrit[headerLabelAuthenticSigningTime] = struct{}{}
	}
	if _, ok := protected[headerLabelExpiry]; ok {
		mustMarkedCrit[headerLabelExpiry] = struct{}{}
	}

	// validate that all required headers(as per spec) are marked as critical
	for _, label := range labels {
		delete(mustMarkedCrit, label)
	}
	if len(mustMarkedCrit) != 0 {
		headers := make([]any, 0, len(mustMarkedCrit))
		for k := range mustMarkedCrit {
			headers = append(headers, k)
		}
		return nil, &signature.InvalidSignatureError{Msg: fmt.Sprintf("these required headers are not marked as critical: %v", headers)}
	}

	// fetch all the extended signed attributes
	systemHeaders := []any{cose.HeaderLabelAlgorithm, cose.HeaderLabelCritical, cose.HeaderLabelContentType,
		headerLabelExpiry, headerLabelSigningScheme, headerLabelSigningTime, headerLabelAuthenticSigningTime}
	var extendedAttributeKeys []any
	for label := range protected {
		if contains(systemHeaders, label) {
			continue
		}
		extendedAttributeKeys = append(extendedAttributeKeys, label)
	}

	return extendedAttributeKeys, nil
}

// generateExtendedAttributes generates []signature.Attribute during
// SignerInfo process.
func generateExtendedAttributes(extendedAttributeKeys []any, protected cose.ProtectedHeader) ([]signature.Attribute, error) {
	criticalHeaders, ok := protected[cose.HeaderLabelCritical].([]any)
	if !ok {
		return nil, &signature.InvalidSignatureError{Msg: "invalid critical headers"}
	}
	var extendedAttr []signature.Attribute
	for _, key := range extendedAttributeKeys {
		extendedAttr = append(extendedAttr, signature.Attribute{
			Key:      key,
			Critical: contains(criticalHeaders, key),
			Value:    protected[key],
		})
	}
	return extendedAttr, nil
}

// contains checks if e is in s
func contains(s []any, e any) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// encodeTime generates a Tag1 Datetime CBOR object and casts it to
// cbor.RawMessage
func encodeTime(t time.Time) (cbor.RawMessage, error) {
	timeCBOR, err := encMode.Marshal(t)
	if err != nil {
		return nil, err
	}

	return cbor.RawMessage(timeCBOR), nil
}

// decodeTime decodes cbor.RawMessage of Tag1 Datetime CBOR object
// into time.Time
//
// For more details: https://github.com/fxamacker/cbor/blob/7704fa5efaf3ef4ac35aff38f50f6ff567793072/decode.go#L52
func decodeTime(timeRaw cbor.RawMessage) (time.Time, error) {
	var t time.Time
	err := decMode.Unmarshal([]byte(timeRaw), &t)
	if err != nil {
		return time.Time{}, err
	}

	return t, nil
}

// parseTime validates Tag1 Datetime in headerMap given label, then returns
// time.Time value from cose.ProtectedHeader.
func parseTime(headerMap map[any]cbor.RawMessage, label string, protected cose.ProtectedHeader) (time.Time, error) {
	switch t := protected[label].(type) {
	// cbor.RawMessage indicates the signing process.
	case cbor.RawMessage:
		return decodeTime(t)
	// time.Time indicates the verififcation process.
	// only need to validate Tag1 Datetime during verification.
	case time.Time:
		rawMsg, ok := headerMap[label]
		if !ok {
			return time.Time{}, fmt.Errorf("headerMap is missing label %q", label)
		}
		rawTag := &cbor.RawTag{}
		//lint:ignore SA1019 we keep it for backwards compatibility
		err := rawTag.UnmarshalCBOR([]byte(rawMsg))
		if err != nil {
			return time.Time{}, fmt.Errorf("header %q time value does not have a tag", label)
		}
		if rawTag.Number != 1 {
			return time.Time{}, errors.New("only Tag `1` Datetime CBOR object is supported")
		}
		return t, nil
	case nil:
		return time.Time{}, fmt.Errorf("protected header %q is missing", label)
	}

	return time.Time{}, errors.New("invalid timeValue type")
}

// generateRawProtectedCBORMap unmarshals rawProtected Header of COSE
// envelope into a headerMap.
func generateRawProtectedCBORMap(rawProtected cbor.RawMessage) (map[any]cbor.RawMessage, error) {
	// empty rawProtected indicates signing process
	if len(rawProtected) == 0 {
		return nil, nil
	}

	var decoded []byte
	err := decMode.Unmarshal(rawProtected, &decoded)
	if err != nil {
		return nil, err
	}
	var headerMap map[any]cbor.RawMessage
	err = cbor.Unmarshal(decoded, &headerMap)
	if err != nil {
		return nil, err
	}

	return headerMap, nil
}

// hashFromCOSEAlgorithm maps the cose algorithm supported by go-cose to hash
func hashFromCOSEAlgorithm(alg cose.Algorithm) (crypto.Hash, error) {
	switch alg {
	case cose.AlgorithmPS256, cose.AlgorithmES256:
		return crypto.SHA256, nil
	case cose.AlgorithmPS384, cose.AlgorithmES384:
		return crypto.SHA384, nil
	case cose.AlgorithmPS512, cose.AlgorithmES512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported cose algorithm %s", alg)
	}
}
