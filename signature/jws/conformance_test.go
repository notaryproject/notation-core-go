package jws

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
)

var (
	// prepare signing time
	signingTime, _ = time.Parse("2006-01-02 15:04:05", "2022-08-29 13:50:00")
	expiry, _      = time.Parse("2006-01-02 15:04:05", "2099-08-29 13:50:00")
	// signedAttributes for signing request
	signedAttributes = signature.SignedAttributes{
		SigningScheme: "notary.x509",
		SigningTime:   signingTime.Truncate(time.Second),
		Expiry:        expiry.Truncate(time.Second).Add(time.Hour * 24),
		ExtendedAttributes: sortAttributes([]signature.Attribute{
			{Key: "signedCritKey1", Value: "signedCritValue1", Critical: true},
			{Key: "signedKey1", Value: "signedValue1", Critical: false},
			{Key: "signedKey2", Value: "signedValue1", Critical: false},
			{Key: "signedKey3", Value: "signedValue1", Critical: false},
			{Key: "signedKey4", Value: "signedValue1", Critical: false},
		}),
	}
	// unsignedAttributes for signing request
	unsignedAttributes = signature.UnsignedAttributes{
		SigningAgent: "NotationConformanceTest/1.0.0",
	}
	// payload to be signed
	payload = signature.Payload{
		ContentType: "application/vnd.cncf.notary.payload.v1+json",
		Content:     []byte("hello JWS"),
	}
	// certificate chain for signer
	leafCertTuple = testhelper.GetECCertTuple(elliptic.P256())
	certs         = []*x509.Certificate{leafCertTuple.Cert, testhelper.GetECRootCertificate().Cert}
)

func conformanceTestSignReq() *signature.SignRequest {
	signer, err := signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
	if err != nil {
		panic(err)
	}

	return &signature.SignRequest{
		Payload:                  payload,
		Signer:                   signer,
		SigningTime:              signedAttributes.SigningTime,
		Expiry:                   signedAttributes.Expiry,
		ExtendedSignedAttributes: signedAttributes.ExtendedAttributes,
		SigningAgent:             unsignedAttributes.SigningAgent,
		SigningScheme:            signedAttributes.SigningScheme,
	}
}

// TestSignedMessageConformance check the conformance between the encoded message
// and the valid encoded message in conformance.json
//
// check payload, protected and signingAgent section
func TestSignedMessageConformance(t *testing.T) {
	// get encoded message
	env := envelope{}
	signReq := conformanceTestSignReq()
	encoded, err := env.Sign(signReq)
	checkNoError(t, err)

	// parse encoded message to be a map
	envMap, err := unmarshalEncodedMessage(encoded)
	checkNoError(t, err)
	// load validation encoded message
	validEnvMap, err := getValidEnvelopeMap()
	checkNoError(t, err)

	// check payload section conformance
	if !reflect.DeepEqual(envMap["payload"], validEnvMap["payload"]) {
		t.Fatal("signed message payload test failed.")
	}

	// check protected section conformance
	if !reflect.DeepEqual(envMap["protected"], validEnvMap["protected"]) {
		t.Fatal("signed message protected test failed.")
	}

	// prepare header
	header, ok := envMap["header"].(map[string]interface{})
	if !ok {
		t.Fatal("signed message header format error.")
	}
	validHeader, ok := validEnvMap["header"].(map[string]interface{})
	if !ok {
		t.Fatal("conformance.json header format error.")
	}
	// check io.cncf.notary.signingAgent conformance
	if !reflect.DeepEqual(header["io.cncf.notary.signingAgent"], validHeader["io.cncf.notary.signingAgent"]) {
		t.Fatal("signed message signingAgent test failed.")
	}
}

func getValidEnvelopeMap() (map[string]interface{}, error) {
	encoded, err := os.ReadFile("./testdata/conformance.json")
	if err != nil {
		return nil, err
	}
	return unmarshalEncodedMessage(encoded)
}

func unmarshalEncodedMessage(encoded []byte) (envelopeMap map[string]interface{}, err error) {
	err = json.Unmarshal(encoded, &envelopeMap)
	return
}

// TestVerifyConformance generates JWS encoded message, parses the encoded message and
// verify the payload, signed/unsigned attributes conformance.
func TestVerifyConformance(t *testing.T) {
	env := envelope{}
	signReq := conformanceTestSignReq()
	encoded, err := env.Sign(signReq)
	checkNoError(t, err)

	newEnv, err := ParseEnvelope(encoded)
	checkNoError(t, err)

	// verify validity
	payload, signerInfo, err := newEnv.Verify()
	checkNoError(t, err)

	// check payload conformance
	verifyPayload(t, payload)

	// check signed/unsigned attributes conformance
	verifyAttributes(t, signerInfo)
}

func verifyPayload(t *testing.T, gotPayload *signature.Payload) {
	if !reflect.DeepEqual(&payload, gotPayload) {
		t.Fatalf("verify payload failed. want: %+v got: %+v\n", &payload, gotPayload)
	}
}

func verifyAttributes(t *testing.T, signerInfo *signature.SignerInfo) {
	// check unsigned attributes
	if !reflect.DeepEqual(&unsignedAttributes, &signerInfo.UnsignedAttributes) {
		t.Fatalf("verify UnsignedAttributes failed. want: %+v got: %+v\n", &unsignedAttributes, &signerInfo.UnsignedAttributes)
	}

	// check signed attributes
	sortAttributes(signerInfo.SignedAttributes.ExtendedAttributes)
	if !reflect.DeepEqual(&signedAttributes, &signerInfo.SignedAttributes) {
		t.Fatalf("verify SignedAttributes failed. want: %+v got: %+v\n", &signedAttributes, &signerInfo.SignedAttributes)
	}

	// check signature algorithm
	keySpec, err := signature.ExtractKeySpec(certs[0])
	checkNoError(t, err)
	if keySpec.SignatureAlgorithm() != signerInfo.SignatureAlgorithm {
		t.Fatalf("verify signature algorithm failed. want: %d got: %d\n", keySpec.SignatureAlgorithm(), signerInfo.SignatureAlgorithm)
	}

	// check certificate chain
	if !reflect.DeepEqual(signerInfo.CertificateChain, certs) {
		t.Fatalf("verify certificate chain failed. want: %+v got: %+v\n", &signerInfo.CertificateChain, certs)
	}
}

func sortAttributes(attributes []signature.Attribute) []signature.Attribute {
	sort.Slice(attributes, func(i, j int) bool {
		return strings.Compare(attributes[i].Key, attributes[j].Key) < 0
	})
	return attributes
}
