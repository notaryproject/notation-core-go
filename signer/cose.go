package signer

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"time"

	cosepkg "github.com/veraison/go-cose"
)

const (
	MediaTypeCOSE SignatureMediaType = "application/cose"
)

var signatureAlgCOSEAlgMap = map[SignatureAlgorithm]int64{
	RSASSA_PSS_SHA_256: -37,
	RSASSA_PSS_SHA_384: -38,
	RSASSA_PSS_SHA_512: -39,
	ECDSA_SHA_256:      -7,
	ECDSA_SHA_384:      -35,
	ECDSA_SHA_512:      -36,
}

var coseAlgSignatureAlgMap = reverseMapCOSE(signatureAlgCOSEAlgMap)

func reverseMapCOSE(m map[SignatureAlgorithm]int64) map[int64]SignatureAlgorithm {
	n := make(map[int64]SignatureAlgorithm, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}

// coseEnvelope implements internalSignatureEnvelope interface.
type coseEnvelope struct {
	internalEnv *cosepkg.Sign1Message
}

func newCoseEnvelopeFromBytes(envelopeBytes []byte) (*coseEnvelope, error) {
	var coseMsg *cosepkg.Sign1Message
	err := coseMsg.UnmarshalCBOR(envelopeBytes)
	if err != nil {
		return nil, err
	}

	return &coseEnvelope{internalEnv: coseMsg}, nil
}

// validateIntegrity implements internalSignatureEnvelope interface
func (cose *coseEnvelope) validateIntegrity() error {
	if cose.internalEnv == nil {
		return SignatureNotFoundError{}
	}
	certs, ok := cose.internalEnv.Headers.Unprotected[cosepkg.HeaderLabelX5Chain].([][]byte)
	if !ok || len(certs) == 0 {
		return MalformedSignatureError{msg: "malformed certificate chain"}
	}

	cert, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return MalformedSignatureError{msg: "malformed leaf certificate"}
	}

	// verify COSE
	publicKeyAlg, err := getSignatureAlgorithm(cert)
	if err != nil || publicKeyAlg == "" {
		return MalformedSignatureError{msg: "malformed PublicKeyAlgorithm"}
	}
	verifier, err := cosepkg.NewVerifier(cosepkg.Algorithm(signatureAlgCOSEAlgMap[publicKeyAlg]), cert.PublicKey)
	if err != nil {
		return MalformedSignatureError{msg: "malformed verifier: " + err.Error()}
	}
	return cose.internalEnv.Verify(nil, verifier)
}

// signPayload implements internalSignatureEnvelope interface
func (cose *coseEnvelope) signPayload(req SignRequest) ([]byte, error) {
	errorFunc := func(s string) error {
		return MalformedSignRequestError{msg: s}
	}

	ks, err := req.SignatureProvider.KeySpec()
	if err != nil {
		return nil, errorFunc(err.Error())
	}
	alg := ks.SignatureAlgorithm()

	protected, err := generateCoseProtectedHeadersMap(req, alg)
	if err != nil {
		return nil, err
	}
	unprotected := generateCoseUnprotectedHeadersMap(req)
	fmt.Println(protected)
	fmt.Println(unprotected)
	coseSigPro := req.SignatureProvider
	// SetHeaders is a Setter implemented by CoseSignatureProvider
	// coseSigPro.SetHeaders(protected, unprotected)
	coseSign1MsgB, certs, err := coseSigPro.Sign(req.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest. error : %v", err)
	}
	if err := validateCertificateChain(certs, req.SigningTime, alg, errorFunc); err != nil {
		return nil, err
	}
	err = cose.internalEnv.UnmarshalCBOR(coseSign1MsgB)
	if err != nil {
		return nil, err
	}
	return coseSign1MsgB, nil

}

// getSignerInfo implements internalSignatureEnvelope interface
func (cose *coseEnvelope) getSignerInfo() (*SignerInfo, error) {
	signInfo := SignerInfo{}
	if cose.internalEnv == nil {
		return nil, SignatureNotFoundError{}
	}

	// parse payload
	payload := cose.internalEnv.Payload
	if len(payload) == 0 {
		return nil, MalformedSignatureError{msg: "Missing payload"}
	}
	signInfo.Payload = payload

	// parse protected headers
	err := processCoseProtectedHeaders(&cose.internalEnv.Headers, &signInfo)
	if err != nil {
		return nil, err
	}

	// parse signature
	sig := cose.internalEnv.Signature
	if len(sig) == 0 {
		return nil, MalformedSignatureError{msg: "Missing signature"}
	}
	signInfo.Signature = sig

	// parse unprotected headers
	// x5chain
	var certChain []*x509.Certificate
	certs, ok := cose.internalEnv.Headers.Unprotected[cosepkg.HeaderLabelX5Chain].([][]byte)
	if !ok || len(certs) == 0 {
		return nil, MalformedSignatureError{msg: "Missing certificate chain"}
	}
	for _, certBytes := range certs {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certChain = append(certChain, cert)
	}
	signInfo.CertificateChain = certChain
	// signingAgent
	signInfo.UnsignedAttributes.SigningAgent = cose.internalEnv.Headers.Unprotected[headerKeySigningAgent].(string)
	// timestampSignature
	signInfo.TimestampSignature = cose.internalEnv.Headers.Unprotected[headerKeyTimeStampSignature].([]byte)

	return &signInfo, nil
}

func generateCoseProtectedHeadersMap(req SignRequest, sigAlg SignatureAlgorithm) (map[interface{}]interface{}, error) {
	protected := make(map[interface{}]interface{})
	// alg
	alg, err := getCOSEAlgo(sigAlg)
	if err != nil {
		return nil, err
	}
	protected[cosepkg.HeaderLabelAlgorithm] = alg

	// crit, signingScheme, expiry, signingTime, authenticSigningTime
	var crit []interface{}
	crit = append(crit, headerKeySigningScheme)
	protected[headerKeySigningScheme] = string(req.SigningScheme)
	if !req.Expiry.IsZero() {
		crit = append(crit, headerKeyExpiry)
		protected[headerKeyExpiry] = uint(req.Expiry.Unix())
	}
	switch req.SigningScheme {
	case SigningSchemeX509:
		protected[headerKeySigningTime] = uint(req.SigningTime.Unix())
	case SigningSchemeX509SigningAuthority:
		crit = append(crit, headerKeyAuthenticSigningTime)
		protected[headerKeyAuthenticSigningTime] = uint(req.SigningTime.Unix())
	}
	protected[cosepkg.HeaderLabelCritical] = crit

	// content type
	protected[cosepkg.HeaderLabelContentType] = string(req.PayloadContentType)

	return protected, nil
}
func generateCoseUnprotectedHeadersMap(req SignRequest) map[interface{}]interface{} {
	unprotected := make(map[interface{}]interface{})
	// Note: cosepkg.HeaderLabelX5Chain REQUIRED but not implemented here
	// as we don't have access to certificates.
	// This should be implemented inside CoseSignatureProvider.Sign()

	// signingAgent
	unprotected[headerKeySigningAgent] = req.SigningAgent

	// TODO: needs to add headerKeyTimeStampSignature here, which requires
	// updates of SignRequest

	return unprotected
}

func processCoseProtectedHeaders(headers *cosepkg.Headers, signInfo *SignerInfo) error {
	if len(headers.RawProtected) == 0 {
		return MalformedSignatureError{msg: "Missing cose envelope protected header"}
	}
	protected := headers.Protected
	// crit
	err := validateCritHeaders(protected)
	if err != nil {
		return err
	}

	// alg
	alg, err := protected.Algorithm()
	if err != nil {
		return err
	}
	sigAlg, ok := coseAlgSignatureAlgMap[int64(alg)]
	if !ok {
		return SignatureAlgoNotSupportedError{alg: strconv.Itoa(int(alg))}
	}
	signInfo.SignatureAlgorithm = sigAlg

	// content type
	cty, ok := protected[cosepkg.HeaderLabelContentType].(string)
	if !ok {
		return MalformedSignatureError{msg: "Missing content type"}
	}
	switch PayloadContentType(cty) {
	case PayloadContentTypeV1:
		signInfo.PayloadContentType = PayloadContentTypeV1
	default:
		// This check is not done in verifySignerInfo method
		return MalformedSignatureError{msg: "Missing or wrong content type"}
	}

	// signingScheme, signingTime
	signScheme, ok := protected[headerKeySigningScheme].(string)
	if !ok {
		return MalformedSignatureError{msg: "Signature missing io.cncf.notary.signingScheme"}
	}
	switch SigningScheme(signScheme) {
	case SigningSchemeX509:
		signTime, ok := protected[headerKeySigningTime].(uint)
		if !ok {
			return MalformedSignatureError{msg: "Missing io.cncf.notary.signingTime under notary.x509"}
		}
		signInfo.SignedAttributes.SigningTime = time.Unix(int64(signTime), 0)
	case SigningSchemeX509SigningAuthority:
		signTime, ok := protected[headerKeyAuthenticSigningTime].(uint)
		if !ok {
			return MalformedSignatureError{msg: "Missing io.cncf.notary.authenticSigningTime under notary.x509.signingAuthority"}
		}
		signInfo.SignedAttributes.SigningTime = time.Unix(int64(signTime), 0)
	default:
		return MalformedSignatureError{msg: "Unsupported signingScheme: " + signScheme}
	}
	signInfo.SigningScheme = SigningScheme(signScheme)

	// expiry
	if exp, ok := protected[headerKeyExpiry].(uint); ok {
		signInfo.SignedAttributes.Expiry = time.Unix(int64(exp), 0)
	}
	return nil
}

// validateCritHeaders does a two-way check, namely:
// 1. validate that all critical headers are present in the protected bucket
// 2. validate that all required headers(as per spec) are marked critical
func validateCritHeaders(protected cosepkg.ProtectedHeader) error {
	// This ensures all critical headers are present in the protected bucket.
	labels, err := protected.Critical()
	if err != nil {
		return err
	}
	mustMarkedCrit := make(map[interface{}]struct{})
	mustMarkedCrit[headerKeySigningScheme] = struct{}{}
	signScheme, ok := protected[headerKeySigningScheme].(string)
	if !ok {
		return MalformedSignatureError{msg: "Signature missing io.cncf.notary.signingScheme"}
	}
	if SigningScheme(signScheme) == SigningSchemeX509SigningAuthority {
		mustMarkedCrit[headerKeyAuthenticSigningTime] = struct{}{}
	}

	if _, ok := protected[headerKeyExpiry].(uint); ok {
		mustMarkedCrit[headerKeyExpiry] = struct{}{}
	}

	for _, label := range labels {
		delete(mustMarkedCrit, label)
	}

	// validate that all required headers(as per spec) are marked critical
	if len(mustMarkedCrit) != 0 {
		// This is not taken care by verifySignerInfo method
		keys := make([]interface{}, 0, len(mustMarkedCrit))
		for k := range mustMarkedCrit {
			keys = append(keys, k)
		}
		return MalformedSignatureError{fmt.Sprintf("these required headers are not marked as critical: %v", keys)}
	}
	return nil
}

func getCOSEAlgo(alg SignatureAlgorithm) (int, error) {
	coseAlg, ok := signatureAlgCOSEAlgMap[alg]
	if !ok {
		return 0, SignatureAlgoNotSupportedError{alg: string(alg)}
	}

	return int(coseAlg), nil
}
