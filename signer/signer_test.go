package signer

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/testhelper"
)

const (
	TestPayload  = "{\"targetArtifact\":{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333\",\"size\":16724,\"annotations\":{\"io.wabbit-networks.buildId\":\"123\"}}}"
	TestValidSig = "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLm1hbmlmZXN0LnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsInNpemUiOjE2NzI0LCJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9fX0\",\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSIsInNpZ25lZENyaXRLZXkxIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5Il0sImN0eSI6ImFwcGxpY2F0aW9uL3ZuZC5jbmNmLm5vdGFyeS5wYXlsb2FkLnYxK2pzb24iLCJpby5jbmNmLm5vdGFyeS5hdXRoZW50aWNTaWduaW5nVGltZSI6IjAwMDEtMDEtMDFUMDA6MDA6MDBaIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IjoiMjAyMi0wNy0xMlQxNjoxMDo1Ny0wNzowMCIsImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdTY2hlbWUiOiJub3RhcnkuZGVmYXVsdC54NTA5IiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiOiIyMDIyLTA3LTExVDE2OjEwOjU3LTA3OjAwIiwic2lnbmVkQ3JpdEtleTEiOiJzaWduZWRWYWx1ZTEiLCJzaWduZWRLZXkxIjoic2lnbmVkS2V5MiJ9\",\"header\":{\"x5c\":[\"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\"],\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"},\"signature\":\"OW8sQepnQ8xI8fTj8swBFV_pLRBPCJpanZ10Ha9upMAJuAXfMCjojUuUOXytxHmA03zKT5uFxqZV1GtMCxksJ17CCSy5sYl78bjarT26KkO6-cEEnmtQQWILOs36Qdyg-0iYSwHG1D14XscfE2pITZksKVbDiwKRAzsXNo-s7jCnZZ_xzMso1oIX3ScIm0FhZAEtsK2bBhXgSzqN441wHZuMMbu5sMP73qQpCn_mlAhDq2wg433Y0QCnzH7PzbhbdSDlDASWVIFaBWZ-oVTMc8oOFe_hDkTVJfb3vLYRMdT7ANPlZEIeQwUboG3jsqhZMXqrCjSABNBl4vqM-IEoVghuU9fJb9LJjZwOoeRrVlF5Et9L3D44KSiyys9Q-e2lllu818M1_1fSxUDjzMMDZCvhRMyNtYOY0sx5A89fk0CLu8MSA-iM9YbLb8D-WinOJstYCTe6UnmnHE9DsPjejEd92MnxqH0dRFmQyFn-nnEBwrlIh8fqNUgFR3r0rOVS\"}\n"
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

	for _, scheme := range []SigningScheme{SigningSchemeX509Default, SigningSchemeX509SigningAuthority} {
		t.Run(fmt.Sprintf("with %s scheme when all arguments are present", scheme), func(t *testing.T) {
			req := newSignRequest(scheme)
			verifySignWithRequest(env, req, t)
		})

		t.Run(fmt.Sprintf("with %s scheme when minimal arguments are present", scheme), func(t *testing.T) {
			lSigner, _ := NewLocalSignatureProvider(getSigningCerts(), testhelper.GetRSALeafCertificate().PrivateKey)
			req := SignRequest{
				Payload:            []byte(TestPayload),
				PayloadContentType: PayloadContentTypeV1,
				SigningScheme:      scheme,
				SigningTime:        time.Now(),
				SignatureProvider:  lSigner,
			}
			verifySignWithRequest(env, req, t)
		})

		t.Run(fmt.Sprintf("with %s scheme when expiry is not present", scheme), func(t *testing.T) {
			req := newSignRequest(scheme)
			req.Expiry = time.Time{}
			verifySignWithRequest(env, req, t)
		})

		t.Run(fmt.Sprintf("with %s scheme when signing agent is not present", scheme), func(t *testing.T) {
			req := newSignRequest(scheme)
			req.SigningAgent = ""
			verifySignWithRequest(env, req, t)
		})

		t.Run(fmt.Sprintf("with %s scheme when extended attributes are not present", scheme), func(t *testing.T) {
			req := newSignRequest(scheme)
			req.ExtendedSignedAttrs = nil
			verifySignWithRequest(env, req, t)
		})

		t.Run(fmt.Sprintf("with %s scheme when verification plugin is not present", scheme), func(t *testing.T) {
			req := newSignRequest(scheme)
			req.VerificationPlugin = ""
			req.VerificationPluginMinVersion = ""
			verifySignWithRequest(env, req, t)
		})

		t.Run(fmt.Sprintf("with %s scheme when verification plugin version is valid", scheme), func(t *testing.T) {
			for _, v := range []string{"", "0.0.0", "1.1.1", "123.456.789", "2.1.0-alpha.1+cheers"} {
				req := getSignRequest()
				req.VerificationPluginMinVersion = v
				verifySignWithRequest(env, req, t)
			}
		})
	}
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

	t.Run("when VerificationPlugin is blank string", func(t *testing.T) {
		req = getSignRequest()
		req.VerificationPlugin = "  "
		verifySignErrorWithRequest(env, req, t)
	})

	t.Run("when VerificationPluginMinVersion is invalid", func(t *testing.T) {
		for _, v := range []string{"  ", "1", "1.1", "1.1.1.1", "v1.1.1", "1.alpha.1"} {
			req = getSignRequest()
			req.VerificationPluginMinVersion = v
			verifySignErrorWithRequest(env, req, t)
		}
	})

	t.Run("when VerificationPluginMinVersion is specified but not VerificationPlugin", func(t *testing.T) {
		req = getSignRequest()
		req.VerificationPlugin = ""
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
	req.SigningTime, err = time.Parse(time.RFC3339, "2022-07-11T16:10:57-07:00")
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

func newSignRequest(scheme SigningScheme) SignRequest {
	lSigner, _ := NewLocalSignatureProvider(getSigningCerts(), testhelper.GetRSALeafCertificate().PrivateKey)

	return SignRequest{
		Payload:            []byte(TestPayload),
		PayloadContentType: PayloadContentTypeV1,
		SigningScheme:      scheme,
		SigningTime:        time.Now(),
		Expiry:             time.Now().AddDate(0, 0, 1),
		ExtendedSignedAttrs: []Attribute{
			{Key: "signedCritKey1", Value: "signedValue1", Critical: true},
			{Key: "signedKey1", Value: "signedKey2", Critical: false}},
		SigningAgent:                 "NotationUnitTest/1.0.0",
		SignatureProvider:            lSigner,
		VerificationPlugin:           "Hola Plugin",
		VerificationPluginMinVersion: "1.1.1",
	}
}

func getSignRequest() SignRequest {
	return newSignRequest(SigningSchemeX509Default)
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
