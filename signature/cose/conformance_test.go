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
	SigningTime        int64       `json:"signingTime"`
	Expiry             int64       `json:"expiry"`
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

	// Not doing conformance check on CertChain and signature fields,
	// becase every time we run this test, a new certChain and signer would be
	// generated, and hence, a new signature would be generated after Sign().
	// Instead, CertChain is verified in verifySignerInfo(), and signature is
	// verified by go-cose's Verify() later on.
	certs := []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}
	certChain := make([]interface{}, len(certs))
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
		SigningTime: time.Unix(sign1.SigningTime, 0),
		Expiry:      time.Unix(sign1.Expiry, 0),
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
	sort.Slice(u, func(p, q int) bool {
		return u[p].Key < u[q].Key
	})
	sort.Slice(v, func(p, q int) bool {
		return v[p].Key < v[q].Key
	})
	return reflect.DeepEqual(u, v)
}

func generateSign1(msg *cose.Sign1Message) *cose.Sign1Message {
	// Not doing conformance check on CertChain and signature fields,
	// becase every time we run this test, a new certChain and signer would be
	// generated, and hence, a new signature would be generated after Sign().
	// Instead, CertChain is verified in verifySignerInfo, and signature is
	// verified by go-cose's Verify().
	newMsg := cose.NewSign1Message()
	newMsg.Headers.Protected = msg.Headers.Protected
	newMsg.Headers.Unprotected["io.cncf.notary.signingAgent"] = msg.Headers.Unprotected["io.cncf.notary.signingAgent"]
	newMsg.Payload = msg.Payload
	// An arbitrary signature
	newMsg.Signature = hexToBytes("31b6cb0cd9c974b39d603465811c2aa3d96a5dff89f80b33cb4e321dc6e68a29b4ba65c00f0f9f22ee4376abfaec2cba6fd21c6881ecaab25775e3fb9226a88cf41660b2d6fd14184540d07ded3744e19ff9dbdd081e15c8f77bb6ca3072ef57141594fad4ea57d206c6b8dd3a6e0a0a7ed764ff08dbcc439bd722e1b3d282921a579a3d860cceea37d633184f9316cb6b4fa4ea550da5ad9e5bf3c2d768a787da76e594290cb10b5b1ead8b7e75967de28e9ff429fe9db814380608a15674f9741563902a620f312213d9dce5c264017cbcb3bb4f8cebee0d5ef32b364f68c11cba5630fac8e3165d06fdebaca095267223c552fe605b4529f25b65f8fa47b010b9096cec275307e82b1062f660a73e07d0b85b978b4a59b5cde51fc9a031b488a3deb38fc312a64ef2ec1250238ae16cfefc00d9aa1ceb938fe6de51f265eebe975c29f4cff8ab0afb40c45e8c985d17347bf20f455851c1a46ab655f51a159cf8910a424c5a8bbdd239e49e43a73c7b5174de29e835063e5e64b459558de5")
	return newMsg
}
