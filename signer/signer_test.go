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
	TestValidSig = "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLm1hbmlmZXN0LnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsInNpemUiOjE2NzI0LCJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9fX0\",\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSIsInNpZ25lZENyaXRLZXkxIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luIiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luTWluVmVyc2lvbiJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkucGF5bG9hZC52MStqc29uIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IjoiMjAyMi0wOC0wNVQxMDowMzoxMS0wNzowMCIsImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdTY2hlbWUiOiJub3RhcnkueDUwOSIsImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIjoiMjAyMi0wOC0wNFQxMDowMzoxMS0wNzowMCIsImlvLmNuY2Yubm90YXJ5LnZlcmlmaWNhdGlvblBsdWdpbiI6IkhvbGEgUGx1Z2luIiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luTWluVmVyc2lvbiI6IjEuMS4xIiwic2lnbmVkQ3JpdEtleTEiOiJzaWduZWRWYWx1ZTEiLCJzaWduZWRLZXkxIjoic2lnbmVkS2V5MiJ9\",\"header\":{\"x5c\":[\"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\"],\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"},\"signature\":\"q8PiYCcO4zNMrnWQ3fPqum3MdejUAmMpPf71pgIuy-6YqP55NnMmzTqyuA4n3xcjdXRNJBpaV5JtTMyudJzDqxs28m6t6zsvwjOiY3HMZhPnC3-E9fws728wMy2daoSHMxT9fliAyTYE5BMezxM3Boxsb1UfEpwd00CITeEw3Ufr5BsVlLSIT79crV5CAiLdwqcJLs1bH7qtg4cqnLTCpf2avSSFCQ1d0_myjrF0VKNxzoNJABchEa2E7tHrHSMm2BRcOf6EWZYoLrmF0DWkwGnRlWpWFkD1I83LvaGLr48aUuUeRK9MJJDfF9EpclKo8Ondf36r8p6Br3ycuqw7d8i4uNic9RQE7ng7CfOSB0cOICA7vQnIEkOw1vb9pcTYL5r2Hgk8KszFeXmt1YAzt65A3YPoFAEoTPfhG6Cl2xfubcA5iGqu26VVOh_L0kB1gWQ749x4gNBlWiB9uZPfBxsFHbKN6k3Km9wgWPdHEvo8VwPvFL34_7BkVb9dyfcA\"}"
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

	for _, scheme := range []SigningScheme{SigningSchemeX509, SigningSchemeX509SigningAuthority} {
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
	req.SigningTime, err = time.Parse(time.RFC3339, "2022-08-04T10:03:11-07:00")
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
	return newSignRequest(SigningSchemeX509)
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
