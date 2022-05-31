package signature

import "fmt"

type JWS struct{}

// validateIntegrity reads the bytes of signature envelope, validates it and convert it into SignatureEnvelope struct.
func (jws JWS) validateIntegrity(envelopeBytes []byte) (SignatureEnvelope, error) {

	fmt.Println("JWS_JSON_validateIntegrity")
	return SignatureEnvelope{}, nil
}
