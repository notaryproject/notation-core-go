package jws

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
)

const (
	certPath = "../testdata/wabbit-networks.io.crt"
	keyPath  = "../testdata/wabbit-networks.io.key"
)

func getSignReq() (*signature.SignRequest, error) {
	// read key / cert pair
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot load cert & key")
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("%q does not contain a signer certificate chain", certPath)
	}
	// parse cert
	certs := make([]*x509.Certificate, len(cert.Certificate))
	for i, c := range cert.Certificate {
		certs[i], err = x509.ParseCertificate(c)
		if err != nil {
			return nil, err
		}
	}
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
	signer, err := signature.NewLocalSigner(certs, cert.PrivateKey)
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
	}, nil

}

func Test_envelope_Verify(t *testing.T) {
	signReq, err := getSignReq()
	if err != nil {
		t.Fatal(err)
	}
	e := NewEnvelope()
	_, err = e.Sign(signReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = e.Verify()
	if err != nil {
		t.Fatal(err)
	}
}

func Test_envelope_Verify_failed(t *testing.T) {
	signReq, err := getSignReq()
	if err != nil {
		t.Fatal(err)
	}
	e := NewEnvelope()
	envelopeBytes, err := e.Sign(signReq)
	if err != nil {
		t.Fatal(err)
	}
	// manipulate envelope
	envelopeBytes[len(envelopeBytes)-10] = 'C'

	newE, err := ParseEnvelope(envelopeBytes)
	if err != nil {
		t.Fatal(err)
	}

	// verify manipulated envelope
	_, _, err = newE.Verify()

	// should get an error
	if err == nil {
		t.Fatalf("should verify failed.")
	}
}
