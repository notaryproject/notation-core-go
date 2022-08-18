package jws

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
)

func getSigningCerts() []*x509.Certificate {
	return []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}
}

func getSignReq(signingScheme signature.SigningScheme) (*signature.SignRequest, error) {
	certs := getSigningCerts()
	payloadBytes := []byte(`{
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333",
    "size": 16724,
    "annotations": {
        "io.wabbit-networks.buildId": "123"
    }
  }
}
	`)
	signer, err := signature.NewLocalSigner(certs, testhelper.GetRSALeafCertificate().PrivateKey)
	if err != nil {
		return nil, err
	}
	return &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: signature.MediaTypePayloadV1,
			Content:     payloadBytes,
		},
		Signer:                   signer,
		SigningTime:              time.Now(),
		Expiry:                   time.Now().Add(time.Hour),
		ExtendedSignedAttributes: nil,
		SigningAgent:             "Notation/1.0.0",
		SigningScheme:            signingScheme,
	}, nil

}

func signCore(signingScheme signature.SigningScheme) ([]byte, error) {
	signReq, err := getSignReq(signingScheme)
	if err != nil {
		return nil, err
	}
	e := NewEnvelope()
	return e.Sign(signReq)
}

func verifyCore(encoded []byte) (*signature.Payload, *signature.SignerInfo, error) {
	env, err := ParseEnvelope(encoded)
	if err != nil {
		return nil, nil, err
	}
	return env.Verify()
}

func Test_envelope_Verify_X509(t *testing.T) {
	encoded, err := signCore(signature.SigningSchemeX509)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = verifyCore(encoded)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_envelope_Verify_X509SigningAuthority(t *testing.T) {
	encoded, err := signCore(signature.SigningSchemeX509SigningAuthority)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = verifyCore(encoded)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_envelope_Verify_failed(t *testing.T) {
	encoded, err := signCore(signature.SigningSchemeX509)
	if err != nil {
		t.Fatal(t)
	}
	// manipulate envelope
	encoded[len(encoded)-10] = 'C'

	// verify manipulated envelope
	_, _, err = verifyCore(encoded)

	// should get an error
	if err == nil {
		t.Fatalf("should verify failed.")
	}
}
