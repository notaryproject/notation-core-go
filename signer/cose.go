package signer

import "github.com/veraison/go-cose"

const (
	MediaTypeCOSE SignatureMediaType = "application/cose"
)

var signatureAlgCOSEAlgMap = map[SignatureAlgorithm]int{
	RSASSA_PSS_SHA_256: -37,
	RSASSA_PSS_SHA_384: -38,
	RSASSA_PSS_SHA_512: -39,
	ECDSA_SHA_256:      -7,
	ECDSA_SHA_384:      -35,
	ECDSA_SHA_512:      -36,
}

var coseAlgSignatureAlgMap = reverseMapCOSE(signatureAlgCOSEAlgMap)

func reverseMapCOSE(m map[SignatureAlgorithm]int) map[int]SignatureAlgorithm {
	n := make(map[int]SignatureAlgorithm, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}

// coseEnvelope implements internalSignatureEnvelope interface.
type coseEnvelope struct {
	internalEnv *cose.Sign1Message
}

func newCoseEnvelopeFromBytes(envelopeBytes []byte) (*coseEnvelope, error) {
	var coseMsg *cose.Sign1Message
	err := coseMsg.UnmarshalCBOR(envelopeBytes)
	if err != nil {
		return nil, err
	}

	return &coseEnvelope{internalEnv: coseMsg}, nil
}

// validateIntegrity implements internalSignatureEnvelope interface
func (cose *coseEnvelope) validateIntegrity() error {
	return nil
}

// signPayload implements internalSignatureEnvelope interface
func (cose *coseEnvelope) signPayload(req SignRequest) ([]byte, error) {
	return nil, nil
}

// getSignerInfo implements internalSignatureEnvelope interface
func (cose *coseEnvelope) getSignerInfo() (*SignerInfo, error) {
	return nil, nil
}
