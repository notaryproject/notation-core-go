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
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/internal/signaturetest"
	"github.com/notaryproject/notation-core-go/testhelper"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/tspclient-go"
	"github.com/veraison/go-cose"
)

const (
	payloadString = "{\"targetArtifact\":{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333\",\"size\":16724,\"annotations\":{\"io.wabbit-networks.buildId\":\"123\"}}}"

	rfc3161TSAurl = "http://timestamp.digicert.com"
)

var (
	signingSchemeString = []string{"notary.x509", "notary.x509.signingAuthority"}
)

func TestParseEnvelopeError(t *testing.T) {
	var emptyCOSE []byte
	_, err := ParseEnvelope(emptyCOSE)
	if err == nil {
		t.Fatalf("ParseEnvelope() expects signature.InvalidSignatureError, but got nil.")
	}

	_, err = ParseEnvelope([]byte("invalid"))
	if err == nil {
		t.Fatalf("ParseEnvelope() expects signature.InvalidSignatureError, but got nil.")
	}
}

func TestSign(t *testing.T) {
	env := createNewEnv(nil)
	for _, signingScheme := range signingSchemeString {
		for _, keyType := range signaturetest.KeyTypes {
			for _, size := range signaturetest.GetKeySizes(keyType) {
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
					signer, err := signaturetest.GetTestLocalSigner(keyType, size)
					if err != nil {
						t.Fatalf("Sign() failed. Error = %s", err)
					}
					signRequest := &signature.SignRequest{
						Payload: signature.Payload{
							ContentType: "application/vnd.cncf.notary.payload.v1+json",
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

	t.Run("with timestamp countersignature request", func(t *testing.T) {
		signRequest, err := newSignRequest("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("newSignRequest() failed. Error = %s", err)
		}
		signRequest.Timestamper, err = tspclient.NewHTTPTimestamper(nil, rfc3161TSAurl)
		if err != nil {
			t.Fatal(err)
		}
		rootCerts, err := nx509.ReadCertificateFile("../../internal/timestamp/testdata/tsaRootCert.cer")
		if err != nil || len(rootCerts) == 0 {
			t.Fatal("failed to read root CA certificate:", err)
		}
		rootCert := rootCerts[0]
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(rootCert)
		signRequest.TSARootCAs = rootCAs
		encoded, err := env.Sign(signRequest)
		if err != nil || encoded == nil {
			t.Fatalf("Sign() failed. Error = %s", err)
		}
		content, err := env.Content()
		if err != nil {
			t.Fatal(err)
		}
		timestampToken := content.SignerInfo.UnsignedAttributes.TimestampSignature
		if len(timestampToken) == 0 {
			t.Fatal("expected timestamp token to be present")
		}
		signedToken, err := tspclient.ParseSignedToken(timestampToken)
		if err != nil {
			t.Fatal(err)
		}
		info, err := signedToken.Info()
		if err != nil {
			t.Fatal(err)
		}
		_, err = info.Validate(content.SignerInfo.Signature)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestSignErrors(t *testing.T) {
	env := createNewEnv(nil)
	// Testing getSigner()
	t.Run("errorLocalSigner: when getSigner has privateKeyError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorLocalSigner{privateKeyError: true}
		_, err = env.Sign(signRequest)
		expected := errors.New("signing key is not supported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("errorLocalSigner: when getSigner has keySpecError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorLocalSigner{keySpecError: true}
		_, err = env.Sign(signRequest)
		expected := errors.New("intended KeySpec() error")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("errorLocalSigner: when getSigner has algError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorLocalSigner{algError: true}
		_, err = env.Sign(signRequest)
		expected := errors.New("RSA: key size 0 not supported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("errorRemoteSigner: when getSigner has keySpecError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{keySpecError: true}
		_, err = env.Sign(signRequest)
		expected := errors.New("intended KeySpec() error")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("errorRemoteSigner: when getSigner has algError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{algError: true}
		_, err = env.Sign(signRequest)
		expected := errors.New("RSA: key size 0 not supported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("errorRemoteSigner: when getSigner has algError and wantEC", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{algError: true, wantEC: true}
		_, err = env.Sign(signRequest)
		expected := errors.New("EC: key size 0 not supported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("errorRemoteSigner: when getSigner has keyTypeError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{keyTypeError: true}
		_, err = env.Sign(signRequest)
		expected := errors.New("key type not supported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
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
		expected := errors.New("signing scheme: require notary.x509 or notary.x509.signingAuthority")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
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
		expected := errors.New("\"io.cncf.notary.signingScheme\" already exists in the protected header")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	// Testing core sign process
	t.Run("when signer has signError", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{signError: true}
		_, err = env.Sign(signRequest)
		expected := errors.New("intended Sign() Error")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when signer returns empty signature", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Signer = &errorRemoteSigner{}
		_, err = env.Sign(signRequest)
		expected := errors.New("empty signature")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
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
		expected := errors.New("intended CertificateChain() error")
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when invalid tsa url is provided", func(t *testing.T) {
		signRequest, err := getSignRequest()
		if err != nil {
			t.Fatalf("getSignRequest() failed. Error = %v", err)
		}
		signRequest.Timestamper = &dummyTimestamper{}
		expected := errors.New("timestamp: failed to timestamp")
		encoded, err := env.Sign(signRequest)
		if !isErrEqual(expected, err) {
			t.Fatalf("Sign() expects error: %v, but got: %v.", expected, err)
		}
		var timestampErr *signature.TimestampError
		if !errors.As(err, &timestampErr) {
			t.Fatal("expected signature.TimestampError")
		}
		if encoded != nil {
			t.Fatal("expected nil signature envelope")
		}
	})
}

func TestVerifyErrors(t *testing.T) {
	t.Run("when signature envelope is not present", func(t *testing.T) {
		env := createNewEnv(nil)
		_, err := env.Verify()
		expected := errors.New("signature envelope is not present")
		if !isErrEqual(expected, err) {
			t.Fatalf("Verify() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope has invalid certificate chain", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = []any{}
		_, err = env.Verify()
		expected := errors.New("certificate chain is not present")
		if !isErrEqual(expected, err) {
			t.Fatalf("Verify() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope leaf certificate has wrong type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = []any{0}
		_, err = env.Verify()
		expected := errors.New("COSE envelope malformed leaf certificate")
		if !isErrEqual(expected, err) {
			t.Fatalf("Verify() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope has malformed leaf certificate", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		certs, ok := env.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([]any)
		if !ok || len(certs) == 0 {
			t.Fatalf("certificate chain is not present")
		}
		certRaw, ok := certs[0].([]byte)
		if !ok {
			t.Fatalf("COSE envelope malformed leaf certificate")
		}
		// Manipulate the leaf certificate
		certRaw[0] += 'A'
		certs[0] = certRaw
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = certs
		_, err = env.Verify()
		expected := errors.New("malformed leaf certificate")
		if !isErrEqual(expected, err) {
			t.Fatalf("Verify() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when getSignatureAlgorithm fails due to unsupported public key", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		certs := []*x509.Certificate{testhelper.GetUnsupportedRSACert().Cert}
		certChain := make([]any, len(certs))
		for i, c := range certs {
			certChain[i] = c.Raw
		}
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = certChain
		_, err = env.Verify()
		expected := errors.New("rsa key size 1024 bits is not supported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Verify() expects error: %v, but got: %v.", expected, err)
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
		_, err = newEnv.Verify()
		expected := errors.New("signature is invalid. Error: verification error")
		if !isErrEqual(expected, err) {
			t.Fatalf("Verify() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when get payload fails", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Protected, cose.HeaderLabelContentType)
		_, err = env.Verify()
		expected := errors.New("missing content type")
		if !isErrEqual(expected, err) {
			t.Fatalf("Verify() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when get signerInfo fails", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[cose.HeaderLabelCritical] = []any{}
		_, err = env.Verify()
		expected := errors.New("empty crit header")
		if !isErrEqual(expected, err) {
			t.Fatalf("Verify() expects error: %v, but got: %v.", expected, err)
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
		_, err = env.Content()
		expected := errors.New("signature envelope is not present")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when missing content type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Protected, cose.HeaderLabelContentType)
		_, err = env.Content()
		expected := errors.New("missing content type")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when content type has wrong type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[cose.HeaderLabelContentType] = 0
		_, err = env.Content()
		expected := errors.New("content type should be of 'tstr' type")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})
}

func TestSignerInfoErrors(t *testing.T) {
	t.Run("when signature missing in COSE envelope", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Signature = []byte{}
		_, err = env.Content()
		expected := errors.New("signature missing in COSE envelope")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	// Testing parseProtectedHeaders
	t.Run("when COSE envelope protected header has empty crit", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[cose.HeaderLabelCritical] = []any{}
		_, err = env.Content()
		expected := errors.New("empty crit header")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope protected header has invalid crit", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[cose.HeaderLabelCritical] = "invalid"
		_, err = env.Content()
		expected := errors.New("invalid crit header")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope protected header signingScheme has wrong type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[headerLabelSigningScheme] = 0
		_, err = env.Content()
		expected := errors.New("invalid signingScheme")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope has required headers that are not marked as critical", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[cose.HeaderLabelCritical] = []any{"io.cncf.notary.expiry"}
		_, err = env.Content()
		expected := errors.New("these required headers are not marked as critical: [io.cncf.notary.signingScheme]")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope protected header missing algorithm", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Protected, cose.HeaderLabelAlgorithm)
		_, err = env.Content()
		expected := errors.New("algorithm not found")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope protected header has unsupported algorithm", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
		_, err = env.Content()
		expected := errors.New("signature algorithm not supported: -8")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope protected header has unsupported signingScheme", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[headerLabelSigningScheme] = "unsupported"
		_, err = env.Content()
		expected := errors.New("unsupported signingScheme: unsupported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when parseTime has Tag0 signingTime", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		raw := generateTestRawMessage(env.base.Headers.RawProtected, headerLabelSigningTime, false, false)
		env.base.Headers.RawProtected = raw
		_, err = env.Content()
		expected := errors.New("invalid signingTime: only Tag `1` Datetime CBOR object is supported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when parseTime has Tag0 expiry", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		raw := generateTestRawMessage(env.base.Headers.RawProtected, headerLabelExpiry, false, false)
		env.base.Headers.RawProtected = raw
		_, err = env.Content()
		expected := errors.New("invalid expiry: only Tag `1` Datetime CBOR object is supported")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when parseTime fails at headerMap missing signgingTime", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		raw := generateTestRawMessage(env.base.Headers.RawProtected, headerLabelSigningTime, true, true)
		env.base.Headers.RawProtected = raw
		_, err = env.Content()
		expected := errors.New("invalid signingTime: headerMap is missing label \"io.cncf.notary.signingTime\"")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when parseTime fails at signgingTime tag validation", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		raw := generateTestRawMessage(env.base.Headers.RawProtected, headerLabelSigningTime, true, false)
		env.base.Headers.RawProtected = raw
		_, err = env.Content()
		expected := errors.New("invalid signingTime: header \"io.cncf.notary.signingTime\" time value does not have a tag")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when parseTime fails at expiry tag validation", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		raw := generateTestRawMessage(env.base.Headers.RawProtected, headerLabelExpiry, true, false)
		env.base.Headers.RawProtected = raw
		_, err = env.Content()
		expected := errors.New("invalid expiry: header \"io.cncf.notary.expiry\" time value does not have a tag")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when decodeTime fails", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		raw := cbor.RawMessage{}
		env.base.Headers.Protected[headerLabelSigningTime] = raw
		raw = nil
		_, err = env.Content()
		expected := errors.New("invalid signingTime: EOF")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope protected header has invalid signingTime", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[headerLabelSigningTime] = "invalid"
		_, err = env.Content()
		expected := errors.New("invalid signingTime: invalid timeValue type")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope protected header missing signingTime", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Protected, headerLabelSigningTime)
		_, err = env.Content()
		expected := errors.New("invalid signingTime: protected header \"io.cncf.notary.signingTime\" is missing")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope protected header has invalid expiry", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Protected[headerLabelExpiry] = "invalid"
		_, err = env.Content()
		expected := errors.New("invalid expiry: invalid timeValue type")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	// Testing unprotected headers
	t.Run("when COSE envelope has invalid certificate chain", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		delete(env.base.Headers.Unprotected, cose.HeaderLabelX5Chain)
		_, err = env.Content()
		expected := errors.New("certificate chain is not present")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope leaf certificate has wrong type", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = []any{0}
		_, err = env.Content()
		expected := errors.New("certificate chain is not present")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})

	t.Run("when COSE envelope has malformed leaf certificate", func(t *testing.T) {
		env, err := getVerifyCOSE("notary.x509", signature.KeyTypeRSA, 3072)
		if err != nil {
			t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
		}
		certs, ok := env.base.Headers.Unprotected[cose.HeaderLabelX5Chain].([]any)
		if !ok || len(certs) == 0 {
			t.Fatalf("certificate chain is not present")
		}
		certRaw, ok := certs[0].([]byte)
		if !ok {
			t.Fatalf("COSE envelope malformed leaf certificate")
		}
		// Manipulate the leaf certificate
		certRaw[0] += 'A'
		certs[0] = certRaw
		env.base.Headers.Unprotected[cose.HeaderLabelX5Chain] = certs
		_, err = env.Content()
		expected := errors.New("x509: malformed certificate")
		if !isErrEqual(expected, err) {
			t.Fatalf("Content() expects error: %v, but got: %v.", expected, err)
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	env := createNewEnv(nil)
	for _, signingScheme := range signingSchemeString {
		for _, keyType := range signaturetest.KeyTypes {
			for _, size := range signaturetest.GetKeySizes(keyType) {
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
					// (Verify with UnmarshalCBOR is covered in the
					// TestSignAndParseVerify() part)
					_, err = env.Verify()
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
		for _, keyType := range signaturetest.KeyTypes {
			for _, size := range signaturetest.GetKeySizes(keyType) {
				t.Run(fmt.Sprintf("with %s scheme, %v keyType, %v keySize", signingScheme, keyType, size), func(t *testing.T) {
					//Verify after UnmarshalCBOR
					env, err := getVerifyCOSE(signingScheme, keyType, size)
					if err != nil {
						t.Fatalf("getVerifyCOSE() failed. Error = %s", err)
					}
					_, err = env.Verify()
					if err != nil {
						t.Fatalf("Verify() failed. Error = %s", err)
					}
				})
			}

		}
	}
}

func TestGenerateExtendedAttributesError(t *testing.T) {
	var extendedAttributeKeys []any
	var protected cose.ProtectedHeader
	_, err := generateExtendedAttributes(extendedAttributeKeys, protected)
	expected := errors.New("invalid critical headers")
	if !isErrEqual(expected, err) {
		t.Fatalf("TestgenerateExtendedAttributesError() expects error: %v, but got: %v.", expected, err)
	}
}

func TestHashFunc(t *testing.T) {
	hash, err := hashFromCOSEAlgorithm(cose.AlgorithmPS256)
	if err != nil || hash.String() != "SHA-256" {
		t.Fatalf("expected SHA-256, but got %s", hash)
	}

	hash, err = hashFromCOSEAlgorithm(cose.AlgorithmPS384)
	if err != nil || hash.String() != "SHA-384" {
		t.Fatalf("expected SHA-384, but got %s", hash)
	}

	hash, err = hashFromCOSEAlgorithm(cose.AlgorithmPS512)
	if err != nil || hash.String() != "SHA-512" {
		t.Fatalf("expected SHA-512, but got %s", hash)
	}

	hash, err = hashFromCOSEAlgorithm(cose.AlgorithmES256)
	if err != nil || hash.String() != "SHA-256" {
		t.Fatalf("expected SHA-256, but got %s", hash)
	}

	hash, err = hashFromCOSEAlgorithm(cose.AlgorithmES384)
	if err != nil || hash.String() != "SHA-384" {
		t.Fatalf("expected SHA-384, but got %s", hash)
	}

	hash, err = hashFromCOSEAlgorithm(cose.AlgorithmES512)
	if err != nil || hash.String() != "SHA-512" {
		t.Fatalf("expected SHA-512, but got %s", hash)
	}

	_, err = hashFromCOSEAlgorithm(cose.AlgorithmEdDSA)
	expectedErrMsg := "unsupported cose algorithm EdDSA"
	if err == nil || err.Error() != expectedErrMsg {
		t.Fatalf("expected %s, but got %s", expectedErrMsg, err)
	}
}

func newSignRequest(signingScheme string, keyType signature.KeyType, size int) (*signature.SignRequest, error) {
	signer, err := signaturetest.GetTestLocalSigner(keyType, size)
	if err != nil {
		return nil, err
	}
	return &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: "application/vnd.cncf.notary.payload.v1+json",
			Content:     []byte(payloadString),
		},
		Signer:      signer,
		SigningTime: time.Now().Truncate(time.Second),
		Expiry:      time.Now().AddDate(0, 0, 1).Truncate(time.Second),
		ExtendedSignedAttributes: []signature.Attribute{
			{Key: "signedCritKey1", Value: "signedCritValue1", Critical: true},
			{Key: "signedKey1", Value: "signedValue1", Critical: false},
		},
		SigningAgent:  "NotationUnitTest/1.0.0",
		SigningScheme: signature.SigningScheme(signingScheme),
	}, nil
}

func getSignRequest() (*signature.SignRequest, error) {
	return newSignRequest("notary.x509", signature.KeyTypeRSA, 3072)
}

func getVerifyCOSE(signingScheme string, keyType signature.KeyType, size int) (envelope, error) {
	signRequest, err := newSignRequest(signingScheme, keyType, size)
	if err != nil {
		return createNewEnv(nil), err
	}
	env := NewEnvelope()
	encoded, err := env.Sign(signRequest)
	if err != nil {
		return createNewEnv(nil), err
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(encoded); err != nil {
		return createNewEnv(nil), err
	}
	newEnv := createNewEnv(&msg)
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
func (s *errorLocalSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	return nil, nil, fmt.Errorf("local signer doesn't support Sign with digest")
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
	signError    bool
	keySpecError bool
	algError     bool
	wantEC       bool
	keyTypeError bool
}

// Sign signs the digest and returns the raw signature
func (s *errorRemoteSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	if s.signError {
		return nil, nil, fmt.Errorf("intended Sign() Error")
	}
	return nil, nil, nil
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

func isErrEqual(wanted, got error) bool {
	if wanted == nil && got == nil {
		return true
	}
	if wanted != nil && got != nil {
		return wanted.Error() == got.Error()
	}
	return false
}

func createNewEnv(msg *cose.Sign1Message) envelope {
	return envelope{
		base: msg,
	}
}

func generateTestRawMessage(raw cbor.RawMessage, label string, unmarshalError bool, mapError bool) cbor.RawMessage {
	var decoded []byte
	decMode.Unmarshal(raw, &decoded)
	cborMap := make(map[string]cbor.RawMessage)
	cbor.Unmarshal(decoded, &cborMap)
	if unmarshalError {
		// "invalid"
		cborMap[label] = cbor.RawMessage([]byte{103, 105, 110, 118, 97, 108, 105, 100})
		if mapError {
			delete(cborMap, label)
		}
	} else {
		// construct Tag0 Datetime CBOR object
		encOptsTag0 := cbor.EncOptions{
			Time:    cbor.TimeRFC3339,
			TimeTag: cbor.EncTagRequired,
		}
		encModeTag0, _ := encOptsTag0.EncMode()

		timeCBOR, _ := encModeTag0.Marshal(time.Now())
		cborMap[label] = timeCBOR
	}
	encoded, err := cbor.Marshal(cborMap)
	if err != nil {
		fmt.Println("err1:", err)
	}
	resRaw, err := encMode.Marshal(encoded)
	if err != nil {
		fmt.Println("err2:", err)
	}

	return resRaw
}

type dummyTimestamper tspclient.Timestamp

func (dts *dummyTimestamper) Timestamp(context.Context, *tspclient.Request) (*tspclient.Response, error) {
	return nil, errors.New("failed to timestamp")
}
