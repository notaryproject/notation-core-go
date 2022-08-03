package signer

import (
	"crypto/x509"

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

// var coseAlgSignatureAlgMap = reverseMapCOSE(signatureAlgCOSEAlgMap)

// func reverseMapCOSE(m map[SignatureAlgorithm]int64) map[int64]SignatureAlgorithm {
// 	n := make(map[int64]SignatureAlgorithm, len(m))
// 	for k, v := range m {
// 		n[v] = k
// 	}
// 	return n
// }

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
	var certs [][]byte
	if certs, ok := cose.internalEnv.Headers.Unprotected[cosepkg.HeaderLabelX5Chain].([][]byte); !ok || len(certs) == 0 {
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
	return nil, nil
}

// getSignerInfo implements internalSignatureEnvelope interface
func (cose *coseEnvelope) getSignerInfo() (*SignerInfo, error) {
	return nil, nil
}
