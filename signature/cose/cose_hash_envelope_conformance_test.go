// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cose

import (
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"runtime"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/veraison/go-cose"
)

func TestConformanceCOSEHashEnvelope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on Windows")
	}
	digested := sha512.Sum512([]byte("hello COSE Hash Envelope"))
	hashEnvelopePayload := cose.HashEnvelopePayload{
		HashAlgorithm:       cose.AlgorithmSHA512,
		HashValue:           digested[:],
		PreimageContentType: "text/plain",
	}
	signReq, err := getCoseHashEnvelopeSignReq()
	if err != nil {
		t.Fatalf("getSignReq() failed. Error = %s", err)
	}

	// enable signing with COSE Hash Envelope as result
	signReq.CoseHashEnvelope = true

	// set the COSE hash envelope payload to be signed
	signReq.CoseHashEnvelopePayload = hashEnvelopePayload
	signReq.Payload = signature.Payload{}

	// create a new COSE envelope
	sigEnv, err := signature.NewEnvelope(MediaTypeEnvelope)
	if err != nil {
		t.Fatal(err)
	}

	// sign and return the COSE Hash Envelope as sig
	sig, err := sigEnv.Sign(signReq)
	if err != nil {
		t.Fatal(err)
	}

	// parse the COSE Hash Envelope
	sigEnv, err = signature.ParseEnvelope(MediaTypeEnvelope, sig)
	if err != nil {
		t.Fatal(err)
	}

	// verify the COSE Hash Envelope
	envContent, err := sigEnv.Verify()
	if err != nil {
		t.Fatal(err)
	}

	// verify signerInfo
	verifySignerInfo(&envContent.SignerInfo, signReq, t)

	// verify COSE hash envelope payload
	if envContent.CoseHashEnvelopePayload.HashAlgorithm != cose.AlgorithmSHA512 {
		t.Fatalf("expected hash algorithm %s, got %s", cose.AlgorithmSHA512, envContent.CoseHashEnvelopePayload.HashAlgorithm)
	}
	if envContent.CoseHashEnvelopePayload.PreimageContentType != "text/plain" {
		t.Fatalf("expected preimage content type %s, got %s", "text/plain", envContent.CoseHashEnvelopePayload.PreimageContentType)
	}
	if !bytes.Equal(envContent.CoseHashEnvelopePayload.HashValue, digested[:]) {
		t.Fatalf("expected hash value %x, got %x", digested[:], envContent.CoseHashEnvelopePayload.HashValue)
	}
}

func getCoseHashEnvelopeSignReq() (*signature.SignRequest, error) {
	leaf := testhelper.GetRSALeafCertificate().Cert
	root := testhelper.GetRSARootCertificate().Cert
	signer, err := signature.NewLocalSigner([]*x509.Certificate{leaf, root}, testhelper.GetRSALeafCertificate().PrivateKey)
	if err != nil {
		return &signature.SignRequest{}, err
	}
	signRequest := &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: "application/vnd.cncf.notary.payload.v1+json",
			Content:     []byte("hello COSE"),
		},
		Signer:      signer,
		SigningTime: leaf.NotBefore.Add(time.Minute * 1).Local(),
		Expiry:      time.Unix(1902017214, 0),
		ExtendedSignedAttributes: []signature.Attribute{
			{Key: "signedCritKey1", Value: "signedCritValue1", Critical: true},
			{Key: "signedKey1", Value: "signedValue1", Critical: false},
		},
		SigningAgent:  "NotationCoseHashEnvelopeConformanceTest/1.0.0",
		SigningScheme: "notary.x509",
	}
	return signRequest, nil
}
