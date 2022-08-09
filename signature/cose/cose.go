package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	cosepkg "github.com/veraison/go-cose"
)

const MediaTypeEnvelope = "application/cose"

// Protected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerKeyExpiry                       = "io.cncf.notary.expiry"
	headerKeySigningTime                  = "io.cncf.notary.signingTime"
	headerKeyAuthenticSigningTime         = "io.cncf.notary.authenticSigningTime"
	headerKeySigningScheme                = "io.cncf.notary.signingScheme"
	headerKeyVerificationPlugin           = "io.cncf.notary.verificationPlugin"
	headerKeyVerificationPluginMinVersion = "io.cncf.notary.verificationPluginMinVersion"
	headerKeyCrit                         = "crit"
	headerKeyAlg                          = "alg"
	headerKeyCty                          = "cty"
)

// Unprotected Headers
// https://github.com/notaryproject/notaryproject/blob/cose-envelope/signature-envelope-cose.md
const (
	headerKeyTimeStampSignature = "io.cncf.notary.timestampSignature"
	headerKeySigningAgent       = "io.cncf.notary.signingAgent"
)

var signatureAlgCOSEAlgMap = map[signature.Algorithm]cosepkg.Algorithm{
	signature.AlgorithmPS256: cosepkg.AlgorithmPS256,
	signature.AlgorithmPS384: cosepkg.AlgorithmES384,
	signature.AlgorithmPS512: cosepkg.AlgorithmPS512,
	signature.AlgorithmES256: cosepkg.AlgorithmES256,
	signature.AlgorithmES384: cosepkg.AlgorithmES384,
	signature.AlgorithmES512: cosepkg.AlgorithmES512,
}

func init() {
	if err := signature.RegisterEnvelopeType(MediaTypeEnvelope, NewEnvelope, ParseEnvelope); err != nil {
		panic(err)
	}
}

type envelope struct {
	internalEnv *cosepkg.Sign1Message
}

type coseSigner struct {
	signer signature.Signer
}

// Algorithm implements cosepkg.Signer interface
func (coseSigner coseSigner) Algorithm() cosepkg.Algorithm {
	keySpec, err := coseSigner.signer.KeySpec()
	if err != nil {
		return 0
	}
	alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return 0
	}
	return alg
}

// Sign implements cosepkg.Signer interface
func (coseSigner coseSigner) Sign(rand io.Reader, digest []byte) ([]byte, error) {
	sig, err := coseSigner.signer.Sign(digest)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Sign implements signature.Envelope interface
// On success, this function returns the signature
func (e *envelope) Sign(req *signature.SignRequest) ([]byte, error) {
	errorFunc := func(s string) error {
		if s != "" {
			return errors.New(s)
		}
		return errors.New("SignRequest is malformed")
	}
	keySpec, err := req.Signer.KeySpec()
	if err != nil {
		return nil, errorFunc(err.Error())
	}
	alg, err := getSignatureAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return nil, errorFunc(err.Error())
	}

	msgToSign := cosepkg.NewSign1Message()
	// payload
	msgToSign.Payload = req.Payload.Content
	// protected headers
	msgToSign.Headers.Protected.SetAlgorithm(alg)
	err = generateCoseProtectedHeaders(req, msgToSign.Headers.Protected)
	if err != nil {
		return nil, err
	}
	// unprotected headers
	msgToSign.Headers.Unprotected[headerKeySigningAgent] = req.SigningAgent
	// TODO: needs to add headerKeyTimeStampSignature here, which requires
	// updates of SignRequest

	signer := req.Signer
	var sig []byte
	var certs []*x509.Certificate
	if localSigner, ok := signer.(signature.LocalSigner); ok {
		// For a local signer, use go-cose
		sig, certs, err = signLocal(req, localSigner, msgToSign, alg)
		if err != nil {
			return nil, err
		}
	} else {
		// Use External plugin's sign
		coseSigner := coseSigner{signer: signer}
		err = msgToSign.Sign(rand.Reader, nil, coseSigner)
		if err != nil {
			return nil, err
		}
		sig, err = msgToSign.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		certs, err = signer.CertificateChain()
		if err != nil {
			return nil, err
		}
	}
	if err := validateCertificateChain(certs, req.SigningTime, alg, errorFunc); err != nil {
		return nil, err
	}
	err = e.internalEnv.UnmarshalCBOR(sig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (e *envelope) Verify() (*signature.Payload, *signature.SignerInfo, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

func (e *envelope) Payload() (*signature.Payload, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *envelope) SignerInfo() (*signature.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func NewEnvelope() signature.Envelope {
	return &base.Envelope{
		Envelope: &envelope{},
	}
}

func ParseEnvelope(envelopeBytes []byte) (signature.Envelope, error) {
	return &base.Envelope{
		Envelope: &envelope{},
		Raw:      envelopeBytes,
	}, nil
}

func validateCertificateChain(certChain []*x509.Certificate, signTime time.Time, expectedAlg cosepkg.Algorithm, f func(string) error) error {
	if len(certChain) == 0 {
		return f("certificate-chain not present or is empty")
	}

	err := nx509.ValidateCodeSigningCertChain(certChain, signTime)
	if err != nil {
		return f(fmt.Sprintf("certificate-chain is invalid, %s", err))
	}

	resSignAlgo, err := getSignatureAlgorithm(certChain[0])
	if err != nil {
		return f(err.Error())
	}
	if resSignAlgo != expectedAlg {
		return f("mismatch between signature algorithm derived from signing certificate and signing algorithm specified")
	}

	return nil
}

// getSignatureAlgorithm picks up a recommended signing algorithm for given certificate.
func getSignatureAlgorithm(signingCert *x509.Certificate) (cosepkg.Algorithm, error) {
	keySpec, err := signature.ExtractKeySpec(signingCert)
	if err != nil {
		return 0, err
	}
	return getSignatureAlgorithmFromKeySpec(keySpec)
}

func getSignatureAlgorithmFromKeySpec(keySpec signature.KeySpec) (cosepkg.Algorithm, error) {
	switch keySpec.Type {
	case signature.KeyTypeRSA:
		switch keySpec.Size {
		case 2048:
			return signatureAlgCOSEAlgMap[signature.AlgorithmPS256], nil
		case 3072:
			return signatureAlgCOSEAlgMap[signature.AlgorithmPS384], nil
		case 4096:
			return signatureAlgCOSEAlgMap[signature.AlgorithmPS512], nil
		default:
			return 0, errors.New("key size not supported")
		}
	case signature.KeyTypeEC:
		switch keySpec.Size {
		case 256:
			return signatureAlgCOSEAlgMap[signature.AlgorithmES256], nil
		case 384:
			return signatureAlgCOSEAlgMap[signature.AlgorithmES384], nil
		case 512:
			return signatureAlgCOSEAlgMap[signature.AlgorithmES512], nil
		default:
			return 0, errors.New("key size not supported")
		}
	default:
		return 0, errors.New("key type not supported")
	}
}

func generateCoseProtectedHeaders(req *signature.SignRequest, protected cosepkg.ProtectedHeader) error {
	// crit, signingScheme, expiry, signingTime, authenticSigningTime
	var crit []interface{}
	crit = append(crit, headerKeySigningScheme)
	protected[headerKeySigningScheme] = string(req.SigningScheme)
	if !req.Expiry.IsZero() {
		crit = append(crit, headerKeyExpiry)
		protected[headerKeyExpiry] = uint(req.Expiry.Unix())
	}
	switch req.SigningScheme {
	case signature.SigningSchemeX509:
		protected[headerKeySigningTime] = uint(req.SigningTime.Unix())
	case signature.SigningSchemeX509SigningAuthority:
		crit = append(crit, headerKeyAuthenticSigningTime)
		protected[headerKeyAuthenticSigningTime] = uint(req.SigningTime.Unix())
	default:
		return errors.New("SigningScheme: require notary.x509 or notary.x509.signingAuthority")
	}
	protected[cosepkg.HeaderLabelCritical] = crit

	// content type
	protected[cosepkg.HeaderLabelContentType] = req.Payload.ContentType

	return nil
}

func signLocal(req *signature.SignRequest, localSigner signature.LocalSigner, msgToSign *cosepkg.Sign1Message, alg cosepkg.Algorithm) ([]byte, []*x509.Certificate, error) {
	certs, err := localSigner.CertificateChain()
	if err != nil {
		return nil, nil, err
	}
	var certChain [][]byte
	for i, c := range certs {
		certChain[i] = c.Raw
	}
	msgToSign.Headers.Unprotected[cosepkg.HeaderLabelX5Chain] = certChain
	switch key := localSigner.PrivateKey().(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		coseSigner, err := cosepkg.NewSigner(alg, key.(crypto.Signer))
		if err != nil {
			return nil, nil, err
		}
		err = msgToSign.Sign(rand.Reader, nil, coseSigner)
		if err != nil {
			return nil, nil, err
		}
	}

	sig, err := msgToSign.MarshalCBOR()
	if err != nil {
		return nil, nil, err
	}

	return sig, certs, nil
}
