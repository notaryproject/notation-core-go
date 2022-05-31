package signature

// Media types of supported signature envelope format.
type SignatureEnvelopeMediaType string

const (
	JWS_JSON SignatureEnvelopeMediaType = "application/jose+json"
)

type VerifierFactory struct{}

// Get returns the signature verifer based on the SignatureEnvelopeMediaType.
func (factory VerifierFactory) Get(signatureMediaType SignatureEnvelopeMediaType) (*Verifier, error) {
	switch signatureMediaType {
	case JWS_JSON:
		return &Verifier{parser: new(JWS)}, nil
	default:
		return nil, &UnsupportedSignatureFormatError{string(signatureMediaType)}
	}
}
