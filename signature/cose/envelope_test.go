package cose

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
	"github.com/veraison/go-cose"
)

const (
	payloadString = "{\"targetArtifact\":{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333\",\"size\":16724,\"annotations\":{\"io.wabbit-networks.buildId\":\"123\"}}}"
)

var (
	signingSchemeString = []string{"notary.x509", "notary.x509.signingAuthority"}
	keyType             = []signature.KeyType{signature.KeyTypeRSA, signature.KeyTypeEC}
)

func TestParseEnvelopeError(t *testing.T) {
	var emptyCOSE []byte
	_, err := ParseEnvelope(emptyCOSE)
	if err == nil {
		t.Fatalf("ParseEnvelope() expects signature.MalformedSignatureError, but got nil.")
	}

	_, err = ParseEnvelope([]byte("Malformed"))
	if err == nil {
		t.Fatalf("ParseEnvelope() expects signature.MalformedSignatureError, but got nil.")
	}
}

func TestSign(t *testing.T) {
	env := envelope{}
	for _, signingScheme := range signingSchemeString {
		for _, keyType := range keyType {
			var size []int
			if keyType == signature.KeyTypeRSA {
				size = []int{2048, 3072, 4096}
			} else {
				size = []int{256, 384, 521}
			}
			for _, size := range size {
				t.Run(fmt.Sprintf("with %s scheme, %v keyType, %v keySize when all arguments are present", signingScheme, keyType, size), func(t *testing.T) {
					signRequest, err := newSignRequest(signingScheme, keyType, size)
					if err != nil {
						t.Fatalf("newSignRequest() failed. Error = %s", err)
					}
					encoded, err := env.Sign(signRequest)
					if err != nil || len(encoded) == 0 {
						t.Fatalf("Sign() failed. Error = %s", err)
					}
				})

				t.Run(fmt.Sprintf("with %s scheme, %v keyType, %v keySize when minimal arguments are present", signingScheme, keyType, size), func(t *testing.T) {
					signer, err := getTestSigner(keyType, size)
					if err != nil {
						t.Fatalf("Sign() failed. Error = %s", err)
					}
					signRequest := &signature.SignRequest{
						Payload: signature.Payload{
							ContentType: signature.MediaTypePayloadV1,
							Content:     []byte(payloadString),
						},
						Signer:        signer,
						SigningTime:   time.Now(),
						SigningScheme: signature.SigningScheme(signingScheme),
					}
					encoded, err := env.Sign(signRequest)
					if err != nil || len(encoded) == 0 {
						t.Fatalf("Sign() failed. Error = %s", err)
					}
				})

				t.Run(fmt.Sprintf("with %s scheme, %v keyType, %v keySize when expiry is not present", signingScheme, keyType, size), func(t *testing.T) {
					signRequest, err := newSignRequest(signingScheme, keyType, size)
					if err != nil {
						t.Fatalf("newSignRequest() failed. Error = %s", err)
					}
					signRequest.Expiry = time.Time{}
					encoded, err := env.Sign(signRequest)
					if err != nil || len(encoded) == 0 {
						t.Fatalf("Sign() failed. Error = %s", err)
					}
				})

				t.Run(fmt.Sprintf("with %s scheme, %v keyType, %v keySize when signingAgent is not present", signingScheme, keyType, size), func(t *testing.T) {
					signRequest, err := newSignRequest(signingScheme, keyType, size)
					if err != nil {
						t.Fatalf("newSignRequest() failed. Error = %s", err)
					}
					signRequest.SigningAgent = ""
					encoded, err := env.Sign(signRequest)
					if err != nil || len(encoded) == 0 {
						t.Fatalf("Sign() failed. Error = %s", err)
					}
				})

				t.Run(fmt.Sprintf("with %s scheme, %v keyType, %v keySize when extended signed attributes are not present", signingScheme, keyType, size), func(t *testing.T) {
					signRequest, err := newSignRequest(signingScheme, keyType, size)
					if err != nil {
						t.Fatalf("newSignRequest() failed. Error = %s", err)
					}
					signRequest.ExtendedSignedAttributes = nil
					encoded, err := env.Sign(signRequest)
					if err != nil || len(encoded) == 0 {
						t.Fatalf("Sign() failed. Error = %s", err)
					}
				})
			}
		}
	}
}

func TestSignErrors(t *testing.T) {
	env := envelope{}
	// Testing getSigner()
	t.Run("errorLocalSigner: when getSigner has privateKeyError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorLocalSigner{privateKeyError: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	t.Run("errorLocalSigner: when getSigner has keySpecError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorLocalSigner{keySpecError: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	t.Run("errorLocalSigner: when getSigner has algError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorLocalSigner{algError: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	t.Run("errorRemoteSigner: when getSigner has keySpecError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{keySpecError: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	t.Run("errorRemoteSigner: when getSigner has algError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{algError: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	t.Run("errorRemoteSigner: when getSigner has algError and wantEC", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{algError: true, wantEC: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	t.Run("errorRemoteSigner: when getSigner has keyTypeError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{keyTypeError: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	// Testing generateProtectedHeaders
	t.Run("when signingScheme is absent", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.SigningScheme = ""
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	t.Run("when an extended signed attribute already exists in the protected header", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.ExtendedSignedAttributes = []signature.Attribute{
			{Key: headerLabelSigningScheme, Value: "notary.x509", Critical: true},
		}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	// Testing generateUnprotectedHeaders
	t.Run("errorLocalSigner: when signer has certificateChainError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorLocalSigner{certificateChainError: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	t.Run("errorRemoteSigner: when signer has certificateChainError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{certificateChainError: true}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})

	// Testing core sign process
	t.Run("when cose.Sign has error", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{}
		_, err = env.Sign(signRequest)
		if err == nil {
			t.Fatalf("Sign() expects error, but got nil.")
		}
	})
}

func TestVerifyErrors(t *testing.T) {
	t.Run("when missing COSE signature envelope", func(t *testing.T) {
		env := envelope{
			base: nil,
		}
		_, _, err := env.Verify()
		if err == nil {
			t.Fatalf("Verify() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope has malformed certificate chain", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = []interface{}{}
		_, _, err = env.Verify()
		if err == nil {
			t.Fatalf("Verify() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope leaf certificate has wrong type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = []interface{}{0}
		_, _, err = env.Verify()
		if err == nil {
			t.Fatalf("Verify() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope has malformed leaf certificate", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		certs, ok := env.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([]interface{})
		if !ok || len(certs) == 0 {
			t.Fatalf("COSE envelope malformed certificate chain")
		}
		certRaw, ok := certs[0].([]byte)
		if !ok {
			t.Fatalf("COSE envelope malformed leaf certificate")
		}
		// Manipulate the leaf certificate
		certRaw[0] += 'A'
		certs[0] = certRaw
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = certs
		_, _, err = env.Verify()
		if err == nil {
			t.Fatalf("Verify() expects error, but got nil.")
		}
	})

	t.Run("when getSignatureAlgorithm fails due to invalid public key type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		certs := []*x509.Certificate{testhelper.GetED25519LeafCertificate().Cert, testhelper.GetED25519RootCertificate().Cert}
		certChain := make([]interface{}, len(certs))
		for i, c := range certs {
			certChain[i] = c.Raw
		}
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChain
		_, _, err = env.Verify()
		if err == nil {
			t.Fatalf("Verify() expects error, but got nil.")
		}
	})

	// Testing core verify process
	t.Run("when tempered signature envelope is provided", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %s", err)
		}
		env := NewEnvelope()
		encoded, err := env.Sign(signRequest)
		if err != nil {
			t.Fatalf("Sign() failed. Error = %s", err)
		}
		encoded[len(encoded)-10] += 'A'
		newEnv, err := ParseEnvelope(encoded)
		if err != nil {
			t.Fatalf("ParseEnvelope() failed. Error = %s", err)
		}
		_, _, err = newEnv.Verify()
		if err == nil {
			t.Fatalf("Verify() expects error, but got nil.")
		}
	})

	t.Run("when get payload fails", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Protected, cose.HeaderLabelContentType)
		_, _, err = env.Verify()
		if err == nil {
			t.Fatalf("Verify() expects error, but got nil.")
		}
	})

	t.Run("when get signerInfo fails", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[cose.HeaderLabelCritical] = []interface{}{}
		_, _, err = env.Verify()
		if err == nil {
			t.Fatalf("Verify() expects error, but got nil.")
		}
	})
}

func TestPayloadErrors(t *testing.T) {
	t.Run("when env.base is nil", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base = nil
		_, err = env.Payload()
		if err == nil {
			t.Fatalf("Payload() expects error, but got nil.")
		}
	})

	t.Run("when missing content type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Protected, cose.HeaderLabelContentType)
		_, err = env.Payload()
		if err == nil {
			t.Fatalf("Payload() expects error, but got nil.")
		}
	})

	t.Run("when content type has wrong type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[cose.HeaderLabelContentType] = 0
		_, err = env.Payload()
		if err == nil {
			t.Fatalf("Payload() expects error, but got nil.")
		}
	})
}

func TestSignerInfoErrors(t *testing.T) {
	t.Run("when env.base is nil", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base = nil
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope missing signature", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Signature = []byte{}
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	// Testing parseProtectedHeaders
	t.Run("when COSE envelope protected header has empty crit", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[cose.HeaderLabelCritical] = []interface{}{}
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope protected header signingScheme has wrong type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[headerLabelSigningScheme] = 0
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope has required headers that are not marked as critical", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Protected, cose.HeaderLabelCritical)
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope has customized protected header key that is not of string type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[0] = "unsupported"
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope protected header missing algorithm", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Protected, cose.HeaderLabelAlgorithm)
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope protected header has unsupported algorithm", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected.SetAlgorithm(cose.AlgorithmEd25519)
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope protected header has unsupported signingScheme", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[headerLabelSigningScheme] = "unsupported"
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope protected header has malformed signingTime", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[headerLabelSigningTime] = "malformed"
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope protected header has malformed expiry", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[headerLabelExpiry] = "malformed"
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	// Testing unprotected headers
	t.Run("when COSE envelope has malformed certificate chain", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Unprotected, cose.HeaderLabelX5Chain)
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope leaf certificate has wrong type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = []interface{}{0}
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

	t.Run("when COSE envelope has malformed leaf certificate", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		certs, ok := env.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([]interface{})
		if !ok || len(certs) == 0 {
			t.Fatalf("COSE envelope malformed certificate chain")
		}
		certRaw, ok := certs[0].([]byte)
		if !ok {
			t.Fatalf("COSE envelope malformed leaf certificate")
		}
		// Manipulate the leaf certificate
		certRaw[0] += 'A'
		certs[0] = certRaw
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = certs
		_, err = env.SignerInfo()
		if err == nil {
			t.Fatalf("SignerInfo() expects error, but got nil.")
		}
	})

}

func TestSignAndVerify(t *testing.T) {
	env := envelope{}
	for _, signingScheme := range signingSchemeString {
		for _, keyType := range keyType {
			var size []int
			if keyType == signature.KeyTypeRSA {
				size = []int{2048, 3072, 4096}
			} else {
				size = []int{256, 384, 521}
			}
			for _, size := range size {
				t.Run(fmt.Sprintf("with %s scheme, %v keyType, %v keySize", signingScheme, keyType, size), func(t *testing.T) {
					// Sign
					signRequest, err := newSignRequest(signingScheme, keyType, size)
					if err != nil {
						t.Fatalf("newSignRequest() failed. Error = %s", err)
					}
					encoded, err := env.Sign(signRequest)
					if err != nil || len(encoded) == 0 {
						t.Fatalf("Sign() faild. Error = %s", err)
					}

					// Verify using the same envelope struct
					_, _, err = env.Verify()
					if err != nil {
						t.Fatalf("Verify() failed. Error = %s", err)
					}
				})
			}
		}
	}
}

func TestSignAndParseVerify(t *testing.T) {
	for _, signingScheme := range signingSchemeString {
		for _, keyType := range keyType {
			var size []int
			if keyType == signature.KeyTypeRSA {
				size = []int{2048, 3072, 4096}
			} else {
				size = []int{256, 384, 521}
			}
			for _, size := range size {
				t.Run(fmt.Sprintf("with %s scheme, %v keyType, %v keySize", signingScheme, keyType, size), func(t *testing.T) {
					//Verify after UnmarshalCBOR
					env, err := getVerifyCOSE(signingScheme, keyType, size)
					if err != nil {
						t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
					}
					_, _, err = env.Verify()
					if err != nil {
						t.Fatalf("Verify() failed. Error = %s", err)
					}
				})
			}

		}
	}
}

func newSignRequest(signingScheme string, keyType signature.KeyType, size int) (*signature.SignRequest, error) {
	signer, err := getTestSigner(keyType, size)
	if err != nil {
		return nil, err
	}
	return &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: signature.MediaTypePayloadV1,
			Content:     []byte(payloadString),
		},
		Signer:      signer,
		SigningTime: time.Now(),
		Expiry:      time.Now().AddDate(0, 0, 1),
		ExtendedSignedAttributes: []signature.Attribute{
			{Key: "signedCritKey1", Value: "signedCritValue1", Critical: true},
			{Key: "signedKey1", Value: "signedValue1", Critical: false},
		},
		SigningAgent:  "NotationUnitTest/1.0.0",
		SigningScheme: signature.SigningScheme(signingScheme),
	}, nil
}

func getTestSigner(keyType signature.KeyType, size int) (signature.Signer, error) {
	switch keyType {
	case signature.KeyTypeEC:
		switch size {
		case 256:
			leafCertTuple := testhelper.GetECCertTuple(elliptic.P256())
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetECRootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		case 384:
			leafCertTuple := testhelper.GetECCertTuple(elliptic.P384())
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetECRootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		case 521:
			leafCertTuple := testhelper.GetECCertTuple(elliptic.P521())
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetECRootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		default:
			return nil, fmt.Errorf("key size not supported")
		}
	case signature.KeyTypeRSA:
		switch size {
		case 2048:
			leafCertTuple := testhelper.GetRSACertTuple(2048)
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetRSARootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		case 3072:
			leafCertTuple := testhelper.GetRSACertTuple(3072)
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetRSARootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		case 4096:
			leafCertTuple := testhelper.GetRSACertTuple(4096)
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetRSARootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		default:
			return nil, fmt.Errorf("key size not supported")
		}
	default:
		return nil, fmt.Errorf("keyType not supported")
	}
}

func getSignRequest() (*signature.SignRequest, error) {
	return newSignRequest("notary.x509", signature.KeyTypeRSA, 3072)
}

func getVerifyCOSE(signingScheme string, keyType signature.KeyType, size int) (envelope, error) {
	signRequest, err := newSignRequest(signingScheme, keyType, size)
	if err != nil {
		return envelope{}, err
	}
	env := NewEnvelope()
	encoded, err := env.Sign(signRequest)
	if err != nil {
		return envelope{}, err
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(encoded); err != nil {
		return envelope{}, err
	}
	newEnv := envelope{
		base: &msg,
	}
	return newEnv, nil
}

// errorLocalSigner implements signature.LocalSigner interface.
type errorLocalSigner struct {
	signature.LocalSigner
	privateKeyError       bool
	keySpecError          bool
	algError              bool
	certificateChainError bool
}

// Sign signs the digest and returns the raw signature
func (s *errorLocalSigner) Sign(digest []byte) ([]byte, error) {
	return nil, fmt.Errorf("local signer doesn't support Sign with digest")
}

// CertificateChain returns the certificate chain
func (s *errorLocalSigner) CertificateChain() ([]*x509.Certificate, error) {
	if s.certificateChainError {
		return nil, fmt.Errorf("intended CertificateChain() error")
	}
	return []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}, nil
}

// KeySpec returns the key specification
func (s *errorLocalSigner) KeySpec() (signature.KeySpec, error) {
	if s.keySpecError {
		return signature.KeySpec{}, fmt.Errorf("intended KeySpec() error")
	}
	if s.algError {
		return signature.KeySpec{
			Type: signature.KeyTypeRSA,
			Size: 0,
		}, nil
	}
	return signature.KeySpec{
		Type: signature.KeyTypeRSA,
		Size: 3072,
	}, nil
}

// PrivateKey returns the private key
func (s *errorLocalSigner) PrivateKey() crypto.PrivateKey {
	if s.privateKeyError {
		return fmt.Errorf("intended PrivateKey() Error")
	}
	return testhelper.GetRSALeafCertificate().PrivateKey
}

// errorRemoteSigner implements signature.Signer interface.
type errorRemoteSigner struct {
	keySpecError          bool
	algError              bool
	certificateChainError bool
	wantEC                bool
	keyTypeError          bool
}

// Sign signs the digest and returns the raw signature
func (s *errorRemoteSigner) Sign(digest []byte) ([]byte, error) {
	return nil, fmt.Errorf("intended Sign() Error")
}

// CertificateChain returns the certificate chain
func (s *errorRemoteSigner) CertificateChain() ([]*x509.Certificate, error) {
	if s.certificateChainError || s.keyTypeError {
		return nil, fmt.Errorf("intended CertificateChain() error")
	}
	if s.wantEC {
		return []*x509.Certificate{testhelper.GetECLeafCertificate().Cert, testhelper.GetECRootCertificate().Cert}, nil
	}
	return []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}, nil
}

// KeySpec returns the key specification
func (s *errorRemoteSigner) KeySpec() (signature.KeySpec, error) {
	if s.keySpecError {
		return signature.KeySpec{}, fmt.Errorf("intended KeySpec() error")
	}
	if s.algError {
		if s.wantEC {
			return signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 0,
			}, nil
		}
		return signature.KeySpec{
			Type: signature.KeyTypeRSA,
			Size: 0,
		}, nil
	}
	if s.keyTypeError {
		return signature.KeySpec{
			Type: 3,
			Size: 3072,
		}, nil
	}
	if s.wantEC {
		return signature.KeySpec{
			Type: signature.KeyTypeEC,
			Size: 384,
		}, nil
	}
	return signature.KeySpec{
		Type: signature.KeyTypeRSA,
		Size: 3072,
	}, nil
}
