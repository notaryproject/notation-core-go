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
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/veraison/go-cose"
)

type sign1 struct {
	Payload            string      `json:"payload"`
	ProtectedHeaders   *cborStruct `json:"protectedHeaders"`
	UnprotectedHeaders *cborStruct `json:"unprotectedHeaders"`
	Output             cborStruct  `json:"expectedOutput"`
}

type cborStruct struct {
	CBORHex  string `json:"cborHex"`
	CBORDiag string `json:"cborDiag"`
}

func TestConformance(t *testing.T) {
	data, err := os.ReadFile("testdata/conformance.json")
	if err != nil {
		t.Fatalf("os.ReadFile() failed. Error = %s", err)
	}
	var sign1 sign1
	err = json.Unmarshal(data, &sign1)
	if err != nil {
		t.Fatalf("json.Unmarshal() failed. Error = %s", err)
	}
	testSign(t, &sign1)
	testVerify(t, &sign1)
}

// testSign does conformance check on COSE_Sign1_Tagged
func testSign(t *testing.T, sign1 *sign1) {
	signRequest, err := getSignReq(sign1)
	if err != nil {
		t.Fatalf("getSignReq() failed. Error = %s", err)
	}
	env := createNewEnv(nil)
	encoded, err := env.Sign(signRequest)
	if err != nil || len(encoded) == 0 {
		t.Fatalf("Sign() faild. Error = %s", err)
	}
	newMsg := generateSign1(env.base)
	got, err := newMsg.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() faild. Error = %s", err)
	}

	// sign1.Output.CBORHex is a manually computed CBOR hex used as ground
	// truth in the conformance test.
	want := hexToBytes(sign1.Output.CBORHex)
	if !bytes.Equal(want, got) {
		t.Fatalf("unexpected output:\nwant: %x\n got: %x", want, got)
	}

	// Verify using the same envelope struct
	// (Verify with UnmarshalCBOR is covered in the testVerify() part)
	_, err = env.Verify()
	if err != nil {
		t.Fatalf("Verify() failed. Error = %s", err)
	}
}

// testVerify does conformance check by decoding COSE_Sign1_Tagged object
// into Sign1Message
func testVerify(t *testing.T, sign1 *sign1) {
	signRequest, err := getSignReq(sign1)
	if err != nil {
		t.Fatalf("getSignReq() failed. Error = %s", err)
	}
	env := createNewEnv(nil)
	encoded, err := env.Sign(signRequest)
	if err != nil || len(encoded) == 0 {
		t.Fatalf("Sign() faild. Error = %s", err)
	}
	//Verify after UnmarshalCBOR
	var msg cose.Sign1Message
	// sign1.Output.CBORHex is a manually computed CBOR hex used as ground
	// truth in the conformance test.
	if err := msg.UnmarshalCBOR(hexToBytes(sign1.Output.CBORHex)); err != nil {
		t.Fatalf("msg.UnmarshalCBOR() failed. Error = %s", err)
	}

	certs := []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}
	certChain := make([]any, len(certs))
	for i, c := range certs {
		certChain[i] = c.Raw
	}
	msg.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChain
	msg.Signature = env.base.Signature

	newEnv := createNewEnv(&msg)
	content, err := newEnv.Verify()
	if err != nil {
		t.Fatalf("Verify() failed. Error = %s", err)
	}
	verifyPayload(&content.Payload, signRequest, t)
	verifySignerInfo(&content.SignerInfo, signRequest, t)
}

func getSignReq(sign1 *sign1) (*signature.SignRequest, error) {
	certs := []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}
	signer, err := signature.NewLocalSigner(certs, testhelper.GetRSALeafCertificate().PrivateKey)
	if err != nil {
		return &signature.SignRequest{}, err
	}
	signRequest := &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: "application/vnd.cncf.notary.payload.v1+json",
			Content:     []byte("hello COSE"),
		},
		Signer:      signer,
		SigningTime: time.Unix(1661321924, 0),
		Expiry:      time.Unix(1661408324, 0),
		ExtendedSignedAttributes: []signature.Attribute{
			{Key: "signedCritKey1", Value: "signedCritValue1", Critical: true},
			{Key: "signedKey1", Value: "signedValue1", Critical: false},
		},
		SigningAgent:  "NotationConformanceTest/1.0.0",
		SigningScheme: "notary.x509",
	}
	return signRequest, nil
}

func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func verifySignerInfo(signInfo *signature.SignerInfo, request *signature.SignRequest, t *testing.T) {
	if request.SigningAgent != signInfo.UnsignedAttributes.SigningAgent {
		t.Fatalf("SigningAgent: expected value %q but found %q", request.SigningAgent, signInfo.UnsignedAttributes.SigningAgent)
	}

	if request.SigningTime.Format(time.RFC3339) != signInfo.SignedAttributes.SigningTime.Format(time.RFC3339) {
		t.Fatalf("SigningTime: expected value %q but found %q", request.SigningTime, signInfo.SignedAttributes.SigningTime)
	}

	if request.Expiry.Format(time.RFC3339) != signInfo.SignedAttributes.Expiry.Format(time.RFC3339) {
		t.Fatalf("Expiry: expected value %q but found %q", request.SigningTime, signInfo.SignedAttributes.Expiry)
	}

	if !areAttrEqual(request.ExtendedSignedAttributes, signInfo.SignedAttributes.ExtendedAttributes) {
		if !(len(request.ExtendedSignedAttributes) == 0 && len(signInfo.SignedAttributes.ExtendedAttributes) == 0) {
			t.Fatalf("Mistmatch between expected and actual ExtendedAttributes")
		}
	}

	signer, err := getSigner(request.Signer)
	if err != nil {
		t.Fatalf("getSigner() failed. Error = %s", err)
	}
	certs := signer.CertificateChain()
	if err != nil || !reflect.DeepEqual(certs, signInfo.CertificateChain) {
		t.Fatalf("Mistmatch between expected and actual CertificateChain")
	}
}

func verifyPayload(payload *signature.Payload, request *signature.SignRequest, t *testing.T) {
	if request.Payload.ContentType != payload.ContentType {
		t.Fatalf("PayloadContentType: expected value %q but found %q", request.Payload.ContentType, payload.ContentType)
	}

	if !bytes.Equal(request.Payload.Content, payload.Content) {
		t.Fatalf("Payload: expected value %q but found %q", request.Payload.Content, payload.Content)
	}
}

func areAttrEqual(u []signature.Attribute, v []signature.Attribute) bool {
	sortCOSEAttributes(u)
	sortCOSEAttributes(v)
	return reflect.DeepEqual(u, v)
}

func generateSign1(msg *cose.Sign1Message) *cose.Sign1Message {
	newMsg := cose.NewSign1Message()
	newMsg.Headers.Protected = msg.Headers.Protected
	newMsg.Headers.Unprotected["io.cncf.notary.signingAgent"] = msg.Headers.Unprotected["io.cncf.notary.signingAgent"]
	newMsg.Payload = msg.Payload
	newMsg.Signature = hexToBytes("5bfec0a345098b9b9b6fb7358face7ab76d191b648ccd19e36fb03c2085ea072ec050d9c6e4fa4845478386d0831a2360d343a1ff027bdd56d496f996b90ac2db9da2460baffec21db7c0ca759ba83ab35cdf521c0926138681bde05277e2976cedbeb4040c930908ef2b113d935378bd3c5e7740119b2b81c59e9c6c24411abdf699547864f68f2e0f6346eeff627bf0d971abdf94e67e12a10134ccbbadfa0ab4031b18705696a9567a0f1f061247fdd00d343ea3a45f63da7f80771612b38fc9877375bcbce28aef1f3ee2b25869722c24737c49d8c6711376dd62b3d32b24d489746e2ba5d25fa76febcc6abf9d2baee67221c85a7a8f8763dadc5e20bb8c5c03a75c68211557813d2d6adea56ec5526f78c18460b1944c8307a4b0ed64a6d6b4abed5067de5a5ad38948a2ea140b01a7762c15b3e63d7d7bdc8962e6c4bff18b34d2a19fc627f02ebf88daf7fb25c55ce1b9ca06ade02f9d60ad16cb306f433f692e598132d67b5d0a02193191d5c9cd52ad81f4e31917e5b5d40ef5ce7")
	return newMsg
}

func sortCOSEAttributes(u []signature.Attribute) {
	sort.Slice(u, func(p, q int) bool {
		switch k1 := u[p].Key.(type) {
		case int:
			switch k2 := u[q].Key.(type) {
			case int:
				return k1 < k2
			case string:
				return false
			}
		case string:
			switch k2 := u[q].Key.(type) {
			case int:
				return true
			case string:
				return k1 < k2
			}
		}
		return false
	})
}
