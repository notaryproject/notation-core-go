package signer

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/testhelper"
)

const (
	TestPayload  = "{\"targetArtifact\":{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333\",\"size\":16724,\"annotations\":{\"io.wabbit-networks.buildId\":\"123\"}}}"
	TestValidSig = "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9LCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsIm1lZGlhVHlwZSI6ImFwcGxpY2F0aW9uL3ZuZC5vY2kuaW1hZ2UubWFuaWZlc3QudjEranNvbiIsInNpemUiOjE2NzI0fX0\"," +
		"\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3RhcnkuZXhwaXJ5Iiwic2lnbmVkQ3JpdEtleTEiXSwiY3R5IjoiYXBwbGljYXRpb24vdm5kLmNuY2Yubm90YXJ5LnYyLmp3cy52MSIsImlvLmNuY2Yubm90YXJ5LmV4cGlyeSI6IjIwMjItMDYtMjVUMTA6NTY6MjItMDc6MDAiLCJpby5jbmNmLm5vdGFyeS5zaWduaW5nVGltZSI6IjIwMjItMDYtMjRUMTA6NTY6MjItMDc6MDAiLCJzaWduZWRDcml0S2V5MSI6InNpZ25lZFZhbHVlMSIsInNpZ25lZEtleTEiOiJzaWduZWRLZXkyIn0\"," +
		"\"header\":{" +
		"	\"x5c\":[" +
		"		\"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\"]," +
		"		\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"}," +
		"\"signature\":\"J9iQDfXM1GYzIazRH36DUgjeBSp1YIv5gqb0evyrp46mRNdsvGxzBvqVM3K1ZYW530wryweL51oVTbXMEh2PWchQZ7g33Be5lgcl82il7rR5D5tpsiSZ7oZsD4LP-Swv6MoYlKW4hKXWTCY9cWLzJhHkGZPiLsyrWUqdBq_0M8BTyx42_MUmAbYrFVKRjZy8PKsFDAaBcZVbdyZWRqVJy4Lfw8n4P0Ry7bDWRkqhI2rXH4o68eSkNF3KGWzQWXTp6uZb7o5HKc3dn3uoNidKvP3kZaM-XfM9Hd9Cw1MxLwvu1Qdjo6MCOatMKxc02cI7LAA6AsRcYfR-vGkVW3bJP9L29GJ-Dufv7dWcC_xCEG7p6lSYcF86haY_iTwSv_IQoKXQrMnwL8yZpbshJBrdjOzojdZBsJ4_Pu7KdNsnTpR-UvnFdIUrPvYek5WwI8jLz9hTVsSzF0aWCnCf7t8sAaUf90CC04kwGP2jnvZKlNcTQpZ56Zl-n43Z6KkC62do\"}\n"
)

var (
	TestTamperedSig = strings.Replace(TestValidSig, "0fX0", "1fX0=", 1)
)

func TestNewSignatureEnvelopeFromBytesError(t *testing.T) {
	_, err := NewSignatureEnvelopeFromBytes([]byte("Malformed"), MediaTypeJWSJson)
	if !(err != nil && errors.As(err, new(MalformedArgumentError))) {
		t.Errorf("Expected MalformedArgumentError but found %q", reflect.TypeOf(err))
	}
}

// Tests various scenarios around generating a signature envelope
func TestSign(t *testing.T) {
	env, err := NewSignatureEnvelope(MediaTypeJWSJson)
	if err != nil {
		t.Fatalf("NewSignatureEnvelope() error = %v", err)
	}

	t.Run("when all arguments are present", func(t *testing.T) {
		req := getSignRequest()
		verifySignWithRequest(env, req, t)
	})

	t.Run("when expiry is not present", func(t *testing.T) {
		req := getSignRequest()
		req.Expiry = time.Time{}
		verifySignWithRequest(env, req, t)
	})

	t.Run("when signing agent is not present", func(t *testing.T) {
		req := getSignRequest()
		req.SigningAgent = ""
		verifySignWithRequest(env, req, t)
	})

	t.Run("when extended attributes are not present", func(t *testing.T) {
		req := getSignRequest()
		req.ExtendedSignedAttrs = nil
		verifySignWithRequest(env, req, t)
	})
}

// Tests various error scenarios around generating a signature envelope
func TestSignErrors(t *testing.T) {
	env, _ := NewSignatureEnvelope(MediaTypeJWSJson)
	req := getSignRequest()

	t.Run("when Payload is absent", func(t *testing.T) {
		req.Payload = nil
		verifySignErrorWithRequest(env, req, t)
	})

	t.Run("when PayloadContentType is absent", func(t *testing.T) {
		req = getSignRequest()
		req.PayloadContentType = ""
		verifySignErrorWithRequest(env, req, t)
	})

	t.Run("when SigningTime is absent", func(t *testing.T) {
		req = getSignRequest()
		req.SigningTime = time.Time{}
		verifySignErrorWithRequest(env, req, t)
	})

	t.Run("when SignatureProvider is absent", func(t *testing.T) {
		req = getSignRequest()
		req.SignatureProvider = nil
		verifySignErrorWithRequest(env, req, t)
	})

	t.Run("when expiry is before singing time", func(t *testing.T) {
		req = getSignRequest()
		req.Expiry = req.SigningTime.AddDate(0, 0, -1)
		verifySignErrorWithRequest(env, req, t)
	})
}

// Tests various scenarios around signature envelope verification
func TestVerify(t *testing.T) {
	certs := "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"
	var certsBytes []byte
	for _, element := range strings.Split(certs, ",") {
		certBytes, _ := base64.StdEncoding.DecodeString(element)
		certsBytes = append(certsBytes, certBytes...)
	}
	signingCerts, _ := x509.ParseCertificates(certsBytes)

	env, err := NewSignatureEnvelopeFromBytes([]byte(TestValidSig), MediaTypeJWSJson)
	if err != nil {
		t.Fatalf("NewSignatureEnvelopeFromBytes() error = %v", err)
	}

	vSignInfo, err := env.Verify()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	info, err := env.GetSignerInfo()
	if err != nil {
		t.Fatalf("GetSignerInfo() error = %v", err)
	}

	req := getSignRequest()
	req.SigningTime, err = time.Parse(time.RFC3339, "2022-06-24T10:56:22-07:00")
	req.Expiry = req.SigningTime.AddDate(0, 0, 1)
	req.SignatureProvider, _ = GetLocalSignatureProvider(signingCerts, testhelper.GetECLeafCertificate().PrivateKey)
	verifySignerInfo(info, req, t)

	if !areSignInfoEqual(vSignInfo, info) {
		t.Fatalf("SignerInfo object returned by Verify() and GetSignerInfo() are different.\n"+
			"Verify=%+v \nGetSignerInfo=%+v", vSignInfo, info)
	}
}

// Tests various error scenarios around signature envelope verification
func TestVerifyErrors(t *testing.T) {
	t.Run("when tempered signature envelope is provided", func(t *testing.T) {
		env, _ := NewSignatureEnvelopeFromBytes([]byte(TestTamperedSig), MediaTypeJWSJson)
		_, err := env.Verify()
		if !(err != nil && errors.As(err, new(SignatureIntegrityError))) {
			t.Errorf("Expected SignatureIntegrityError but found %T", err)
		}
	})

	t.Run("when malformed signature envelope is provided", func(t *testing.T) {
		env, _ := NewSignatureEnvelopeFromBytes([]byte("{}"), MediaTypeJWSJson)
		_, err := env.Verify()
		if !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected SignatureIntegrityError but found %T", err)
		}
	})
}

// Tests various scenarios around sign first and then verify envelope verification
func TestSignAndVerify(t *testing.T) {
	t.Run("with RSA certificate", func(t *testing.T) {
		// Sign
		env, err := NewSignatureEnvelope(MediaTypeJWSJson)
		if err != nil {
			t.Fatalf("NewSignatureEnvelope() error = %v", err)
		}

		req := getSignRequest()
		sig, err := env.Sign(req)
		if err != nil || len(sig) == 0 {
			t.Fatalf("Sign() error = %v", err)
		}

		// Verify using same env struct
		_, err = env.Verify()
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}

		info, err := env.GetSignerInfo()
		if err != nil {
			t.Fatalf("GetSignerInfo() error = %v", err)
		}

		verifySignerInfo(info, req, t)
	})

	t.Run("with EC certificate", func(t *testing.T) {
		// Sign
		env, err := NewSignatureEnvelope(MediaTypeJWSJson)
		if err != nil {
			t.Fatalf("NewSignatureEnvelope() error = %v", err)
		}

		req := getSignRequest()
		certs := []*x509.Certificate{testhelper.GetECLeafCertificate().Cert, testhelper.GetECRootCertificate().Cert}
		req.SignatureProvider, _ = GetLocalSignatureProvider(certs, testhelper.GetECLeafCertificate().PrivateKey)
		sig, err := env.Sign(req)
		if err != nil || len(sig) == 0 {
			t.Fatalf("Sign() error = %v", err)
		}

		// Verify using same env struct
		_, err = env.Verify()
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}

		info, err := env.GetSignerInfo()
		if err != nil {
			t.Fatalf("GetSignerInfo() error = %v", err)
		}

		verifySignerInfo(info, req, t)
	})
}

// Tests various error scenarios around GetSignerInfo method
func TestGetSignerInfoErrors(t *testing.T) {
	env, _ := NewSignatureEnvelope(MediaTypeJWSJson)
	t.Run("when called GetSignerInfo before sign or verify.", func(t *testing.T) {
		_, err := env.GetSignerInfo()
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("Expected SignatureNotFoundError but found %q", err)
		}
	})

	t.Run("when called GetSignerInfo after failed sign or verify call.", func(t *testing.T) {
		req := getSignRequest()
		req.SignatureProvider = nil
		env.Sign(req)
		env.Verify()
		_, err := env.GetSignerInfo()
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("Expected SignatureNotFoundError but but found %q", reflect.TypeOf(err))
		}
	})
}

func TestVerifyAuthenticity(t *testing.T) {
	env, _ := NewSignatureEnvelope(MediaTypeJWSJson)
	req := getSignRequest()
	env.Sign(req)
	info, _ := env.GetSignerInfo()

	t.Run("when trustedCerts is root cert", func(t *testing.T) {
		certs := getSigningCerts()
		root := certs[len(certs)-1]
		trust, err := VerifyAuthenticity(info, []*x509.Certificate{root, testhelper.GetECRootCertificate().Cert})
		if err != nil {
			t.Fatalf("VerifyAuthenticity() error = %v", err)
		}

		if !trust.Equal(root) {
			t.Fatalf("Expected cert with subject %q but found cert with subject %q",
				root.Subject, trust.Subject)
		}
	})

	t.Run("when trustedCerts is leaf cert", func(t *testing.T) {
		leaf := getSigningCerts()[0]
		trust, err := VerifyAuthenticity(info, []*x509.Certificate{leaf, testhelper.GetECRootCertificate().Cert})
		if err != nil {
			t.Fatalf("VerifyAuthenticity() error = %v", err)
		}

		if !trust.Equal(leaf) {
			t.Fatalf("Expected cert with subject %q but found cert with subject %q",
				leaf.Subject, trust.Subject)
		}
	})
}

func TestVerifyAuthenticityError(t *testing.T) {
	env, _ := NewSignatureEnvelope(MediaTypeJWSJson)
	req := getSignRequest()
	env.Sign(req)
	info, _ := env.GetSignerInfo()

	t.Run("when trustedCerts are not trusted", func(t *testing.T) {
		_, err := VerifyAuthenticity(info, []*x509.Certificate{testhelper.GetECRootCertificate().Cert})
		if !(err != nil && errors.As(err, new(SignatureAuthenticityError))) {
			t.Errorf("Expected SignatureAuthenticityError but found %T", err)
		}
	})

	t.Run("when trustedCerts is absent", func(t *testing.T) {
		_, err := VerifyAuthenticity(info, []*x509.Certificate{})
		if !(err != nil && errors.As(err, new(MalformedArgumentError))) {
			t.Errorf("Expected MalformedArgumentError but found %T", err)
		}
	})

	t.Run("when trustedCerts array is of zero length", func(t *testing.T) {
		_, err := VerifyAuthenticity(info, nil)
		if !(err != nil && errors.As(err, new(MalformedArgumentError))) {
			t.Errorf("Expected MalformedArgumentError but found %T", err)
		}
	})

	t.Run("when SignerInfo is absent", func(t *testing.T) {
		_, err := VerifyAuthenticity(nil, []*x509.Certificate{testhelper.GetECRootCertificate().Cert})
		if !(err != nil && errors.As(err, new(MalformedArgumentError))) {
			t.Errorf("Expected MalformedArgumentError but found %T", err)
		}
	})

	t.Run("when cert chain in signer info is absent", func(t *testing.T) {
		signInfoCopy := *info
		signInfoCopy.CertificateChain = nil
		_, err := VerifyAuthenticity(&signInfoCopy, nil)
		if !(err != nil && errors.As(err, new(MalformedArgumentError))) {
			t.Errorf("Expected MalformedArgumentError but found %T", err)
		}
	})

}

func getSignRequest() SignRequest {
	lSigner, _ := GetLocalSignatureProvider(getSigningCerts(), testhelper.GetRSALeafCertificate().PrivateKey)

	return SignRequest{
		Payload:            []byte(TestPayload),
		PayloadContentType: PayloadContentTypeJWSV1,
		SigningTime:        time.Now(),
		Expiry:             time.Now().AddDate(0, 0, 1),
		ExtendedSignedAttrs: []Attribute{
			{Key: "signedCritKey1", Value: "signedValue1", Critical: true},
			{Key: "signedKey1", Value: "signedKey2", Critical: false}},
		SigningAgent:      "NotationUnitTest/1.0.0",
		SignatureProvider: lSigner,
	}
}

func getSigningCerts() []*x509.Certificate {
	return []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}
}

func verifySignerInfo(signInfo *SignerInfo, request SignRequest, t *testing.T) {
	if request.SigningAgent != signInfo.UnsignedAttributes.SigningAgent {
		t.Errorf("SigningAgent: expected value %q but found %q", request.SigningAgent, signInfo.UnsignedAttributes.SigningAgent)
	}

	if request.SigningTime.Format(time.RFC3339) != signInfo.SignedAttributes.SigningTime.Format(time.RFC3339) {
		t.Errorf("SigningTime: expected value %q but found %q", request.SigningTime, signInfo.SignedAttributes.SigningTime)
	}

	if request.Expiry.Format(time.RFC3339) != signInfo.SignedAttributes.Expiry.Format(time.RFC3339) {
		t.Errorf("Expiry: expected value %q but found %q", request.SigningTime, signInfo.SignedAttributes.Expiry)
	}

	if !areAttrEqual(request.ExtendedSignedAttrs, signInfo.SignedAttributes.ExtendedAttributes) {
		if !(len(request.ExtendedSignedAttrs) == 0 && len(signInfo.SignedAttributes.ExtendedAttributes) == 0) {
			t.Errorf("Mistmatch between expected and actual ExtendedAttributes")
		}
	}

	if request.PayloadContentType != signInfo.PayloadContentType {
		t.Errorf("PayloadContentType: expected value %q but found %q", request.PayloadContentType, signInfo.PayloadContentType)
	}

	_, certs, err := request.SignatureProvider.Sign([]byte(""))
	if err != nil || !reflect.DeepEqual(certs, signInfo.CertificateChain) {
		t.Errorf("Mistmatch between expected and actual CertificateChain")
	}

	// The input payload and the payload signed are different because the jwt library we are using converts
	// payload to map and then to json but the content of payload should be same
	var requestPay map[string]interface{}
	if err := json.Unmarshal(request.Payload, &requestPay); err != nil {
		t.Log(err)
	}

	var signerInfoPay map[string]interface{}
	if err := json.Unmarshal(signInfo.Payload, &signerInfoPay); err != nil {
		t.Log(err)
	}

	if !reflect.DeepEqual(signerInfoPay, signerInfoPay) {
		t.Errorf("Payload: expected value %q but found %q", requestPay, signerInfoPay)
	}
}

func verifySignWithRequest(env *SignatureEnvelope, req SignRequest, t *testing.T) {
	sig, err := env.Sign(req)
	if err != nil || len(sig) == 0 {
		t.Fatalf("Sign() error = %v", err)
	}

	info, err := env.GetSignerInfo()
	if err != nil {
		t.Fatalf("GetSignerInfo() error = %v", err)
	}

	verifySignerInfo(info, req, t)
}

func verifySignErrorWithRequest(env *SignatureEnvelope, req SignRequest, t *testing.T) {
	_, err := env.Sign(req)
	if !(err != nil && errors.As(err, new(MalformedSignRequestError))) {
		t.Errorf("Expected MalformedArgumentError but but found %q", reflect.TypeOf(err))
	}
}

func areAttrEqual(u []Attribute, v []Attribute) bool {
	sort.Slice(u, func(p, q int) bool {
		return u[p].Key < u[q].Key
	})
	sort.Slice(v, func(p, q int) bool {
		return v[p].Key < v[q].Key
	})
	return reflect.DeepEqual(u, v)
}

func areSignInfoEqual(u *SignerInfo, v *SignerInfo) bool {
	uExtAttr := u.SignedAttributes.ExtendedAttributes
	vExtAttr := v.SignedAttributes.ExtendedAttributes
	u.SignedAttributes.ExtendedAttributes = nil
	v.SignedAttributes.ExtendedAttributes = nil
	return reflect.DeepEqual(u, v) && areAttrEqual(uExtAttr, vExtAttr)
}
