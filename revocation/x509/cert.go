package x509

// Purpose is an enum for purpose of the certificate chain whose revocation
// status is checked
type Purpose int

const (
	// PurposeCodeSigning means the certificate chain is a code signing chain
	PurposeCodeSigning Purpose = iota

	// PurposeTimestamping means the certificate chain is a timestamping chain
	PurposeTimestamping
)
