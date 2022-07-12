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
	TestValidSig = "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLm1hbmlmZXN0LnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsInNpemUiOjE2NzI0LCJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9fX0\",\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3RhcnkuZXhwaXJ5Iiwic2lnbmVkQ3JpdEtleTEiXSwiY3R5IjoiYXBwbGljYXRpb24vdm5kLmNuY2Yubm90YXJ5LnBheWxvYWQudjEranNvbiIsImlvLmNuY2Yubm90YXJ5LmV4cGlyeSI6IjIwMjItMDctMTJUMTM6MDY6MTgtMDc6MDAiLCJpby5jbmNmLm5vdGFyeS5zaWduaW5nVGltZSI6IjIwMjItMDctMTFUMTM6MDY6MTgtMDc6MDAiLCJzaWduZWRDcml0S2V5MSI6InNpZ25lZFZhbHVlMSIsInNpZ25lZEtleTEiOiJzaWduZWRLZXkyIn0\",\"header\":{\"x5c\":[\"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\"],\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"},\"signature\":\"hTQd14wr0WzrNQjdyex76iXjfGfAhYPyl7mczD_KbNZPkDah2tBeXHQKTAJ4tmbCQxQ5Wh3DpQMphkD4wS10BWKED4Fex2w2hiN0m2FovehMnCkVgvjBWOKei2R0Ubwu_M0LhHUawqj2QohaoXjO6OzKjZlTsmYrr-dJAIgatKYe9ERwZRSQlrhwQNsW10cNaSmPckoRpVx26fzfSVZTO7nRKNj-PqyKOgoWjxee9A9bIPdTdCN_ihFEskTIp3nOhBFRbDOUlDp_QSRZ-BYCSjNMW4GkeWbYTNJwn_EjVhMDr4uX0YubzGwW-oW3wmJLRS406ICt_r7z2fpWZVwHdh1cJCKlaAwEw7F4FCQCGrvtN6_hjNqMtiRUOMtMa80mm5By0rBgMmEy8_JipfaVnAEkQpyk4UWVGIK4IrPIHyAo92LxIVftmiLgvLXSjsC7W82VToJws7uWtgA0niW3LjD7DPf8bGXu_vQHFReQWB5S9Vc2Bz8nsPxg3MSJclit\"}\n"
)

var (
	TestTamperedSig = strings.Replace(TestValidSig, "6eyJt", "1fX0=", 1)
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
	req.SigningTime, err = time.Parse(time.RFC3339, "2022-07-11T13:06:18-07:00")
	req.Expiry = req.SigningTime.AddDate(0, 0, 1)
	req.SignatureProvider, _ = NewLocalSignatureProvider(signingCerts, testhelper.GetECLeafCertificate().PrivateKey)
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
		req.SignatureProvider, _ = NewLocalSignatureProvider(certs, testhelper.GetECLeafCertificate().PrivateKey)
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
	lSigner, _ := NewLocalSignatureProvider(getSigningCerts(), testhelper.GetRSALeafCertificate().PrivateKey)

	return SignRequest{
		Payload:            []byte(TestPayload),
		PayloadContentType: PayloadContentTypeV1,
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
