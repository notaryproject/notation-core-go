package cose

import (
	"crypto/x509"
	"reflect"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/base"
	"github.com/notaryproject/notation-core-go/testhelper"
)

const (
	TestPayload = "{\"targetArtifact\":{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333\",\"size\":16724,\"annotations\":{\"io.wabbit-networks.buildId\":\"123\"}}}"
)

var signingSchemeString = []string{"notary.x509", "notary.x509.signingAuthority"}

func getSignRequest(signingScheme string) (*signature.SignRequest, error) {
	certs := getSigningCerts()
	signer, err := signature.NewLocalSigner(certs, testhelper.GetRSALeafCertificate().PrivateKey)
	if err != nil {
		return nil, err
	}
	return &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: signature.MediaTypePayloadV1,
			Content:     []byte(TestPayload),
		},
		Signer:      signer,
		SigningTime: time.Now(),
		Expiry:      time.Now().AddDate(0, 0, 1),
		ExtendedSignedAttributes: []signature.Attribute{
			{Key: "signedCritKey1", Value: "signedCritValue1", Critical: true},
			{Key: "signedKey1", Value: "signedValue1", Critical: false}},
		SigningAgent:  "NotationUnitTest/1.0.0",
		SigningScheme: signature.SigningScheme(signingScheme),
	}, nil
}

func getSigningCerts() []*x509.Certificate {
	return []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}
}

func TestNewEnvelope(t *testing.T) {
	env := NewEnvelope()
	b, ok := env.(*base.Envelope)
	if !ok {
		t.Fatalf("NewEnvelope() failed. env is not a base envelope.")
	}
	wanted := &base.Envelope{
		Envelope: &envelope{},
	}
	if !reflect.DeepEqual(wanted.Envelope, b.Envelope) {
		t.Fatalf("NewEnvelope() failed. Wants: %v, Got: %v", wanted.Envelope, b.Envelope)
	}
	if !reflect.DeepEqual(wanted.Raw, b.Raw) {
		t.Fatalf("NewEnvelope() failed. Wants: %v, Got: %v", wanted.Raw, b.Raw)
	}

}

func TestParseEnvelopeError(t *testing.T) {
	_, err := ParseEnvelope([]byte("Malformed"))
	if err == nil {
		t.Fatalf("ParseEnvelope() expects signature.MalformedSignatureError, but got nil.")
	}
}

func TestSignAndVerify(t *testing.T) {
	for _, signingScheme := range signingSchemeString {
		signRequest, err := getSignRequest(signingScheme)
		if err != nil {
			t.Fatalf("getSignRequest(). Error = %s", err)
		}
		env := NewEnvelope()
		encoded, err := env.Sign(signRequest)
		if err != nil {
			t.Fatalf("sign failed. Error = %s", err)
		}
		env, err = ParseEnvelope(encoded)
		if err != nil {
			t.Fatalf("parse envelope failed. Error = %s", err)
		}
		_, _, err = env.Verify()
		if err != nil {
			t.Fatalf("verify failed. Error = %s", err)
		}
	}
}

func TestVerifyError(t *testing.T) {
	for _, signingScheme := range signingSchemeString {
		SignRequest, err := getSignRequest(signingScheme)
		if err != nil {
			t.Fatalf("getSignRequest(). Error = %s", err)
		}
		env := NewEnvelope()
		encoded, err := env.Sign(SignRequest)
		if err != nil {
			t.Fatalf("sign failed. Error = %s", err)
		}
		// tamper the signature envelope
		encoded[len(encoded)-10] += 'A'
		newEnv, err := ParseEnvelope(encoded)
		if err != nil {
			t.Fatalf("parse envelope failed. Error = %s", err)
		}
		_, _, err = newEnv.Verify()
		// expect to get an error
		if err == nil {
			t.Fatalf("should failed verify")
		}
	}
}

func TestPayloadAndSignerInfo(t *testing.T) {
	for _, signingScheme := range signingSchemeString {
		SignRequest, err := getSignRequest(signingScheme)
		if err != nil {
			t.Fatalf("getSignRequest(). Error = %s", err)
		}
		env := NewEnvelope()
		encoded, err := env.Sign(SignRequest)
		if err != nil {
			t.Fatalf("sign failed. Error = %s", err)
		}
		env, err = ParseEnvelope(encoded)
		if err != nil {
			t.Fatalf("parse envelope failed. Error = %s", err)
		}
		_, err = env.SignerInfo()
		if err != nil {
			t.Fatalf("payload and/or signerInfo failed. Error = %s", err)
		}
	}
}
