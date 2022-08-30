package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/signaturetest"
	"github.com/notaryproject/notation-core-go/testhelper"
)

// remoteMockSigner is used to mock remote signer
type remoteMockSigner struct {
	privateKey crypto.PrivateKey
	certs      []*x509.Certificate
}

// Sign signs the digest and returns the raw signature
func (signer *remoteMockSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	// calculate hash
	keySpec, err := signer.KeySpec()
	if err != nil {
		return nil, nil, err
	}

	// calculate hash
	hasher := keySpec.SignatureAlgorithm().Hash().HashFunc()
	h := hasher.New()
	h.Write(payload)
	hash := h.Sum(nil)

	// sign
	switch key := signer.privateKey.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand.Reader, key, hasher.HashFunc(), hash, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			return nil, nil, err
		}
		return sig, signer.certs, nil
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			return nil, nil, err
		}

		curveBits := key.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes += 1
		}

		out := make([]byte, 2*keyBytes)
		r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
		s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.
		return out, signer.certs, nil
	}

	return nil, nil, &signature.UnsupportedSigningKeyError{}
}

// KeySpec returns the key specification
func (signer *remoteMockSigner) KeySpec() (signature.KeySpec, error) {
	return signature.ExtractKeySpec(signer.certs[0])
}

func checkNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func checkErrorEqual(t *testing.T, want, got string) {
	if got != want {
		t.Fatalf("want: %v, got: %v\n", want, got)
	}
}

var (
	extSignedAttr = []signature.Attribute{
		{
			Key:      "testKey",
			Critical: true,
			Value:    "testValue",
		},
		{
			Key:      "testKey2",
			Critical: false,
			Value:    "testValue2",
		},
	}
	extSignedAttrRepeated = []signature.Attribute{
		{
			Key:      "cty",
			Critical: false,
			Value:    "testValue2",
		},
	}
	extSignedAttrErrorValue = []signature.Attribute{
		{
			Key:      "add",
			Critical: false,
			Value:    math.Inf(1),
		},
	}
)

func getSigningCerts() []*x509.Certificate {
	return []*x509.Certificate{testhelper.GetRSALeafCertificate().Cert, testhelper.GetRSARootCertificate().Cert}
}

func getSignReq(signingScheme signature.SigningScheme, signer signature.Signer, extendedSignedAttribute []signature.Attribute) (*signature.SignRequest, error) {
	payloadBytes := []byte(`{
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:73c803930ea3ba1e54bc25c2bdc53edd0284c62ed651fe7b00369da519a3c333",
    "size": 16724,
    "annotations": {
        "io.wabbit-networks.buildId": "123"
    }
  }
}`)
	return &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: signature.MediaTypePayloadV1,
			Content:     payloadBytes,
		},
		Signer:                   signer,
		SigningTime:              time.Now(),
		Expiry:                   time.Now().Add(time.Hour),
		ExtendedSignedAttributes: extendedSignedAttribute,
		SigningAgent:             "Notation/1.0.0",
		SigningScheme:            signingScheme,
	}, nil
}

func getSigner(isLocal bool, certs []*x509.Certificate, privateKey *rsa.PrivateKey) (signature.Signer, error) {
	if certs == nil {
		certs = getSigningCerts()
	}
	if privateKey == nil {
		privateKey = testhelper.GetRSALeafCertificate().PrivateKey
	}
	if isLocal {
		return signature.NewLocalSigner(certs, privateKey)
	}

	return &remoteMockSigner{
		certs:      certs,
		privateKey: privateKey,
	}, nil
}

func getEnvelope(signingScheme signature.SigningScheme, isLocal bool, extendedSignedAttribute []signature.Attribute) (*jwsEnvelope, error) {
	encoded, err := getEncodedMessage(signingScheme, isLocal, extendedSignedAttribute)
	if err != nil {
		return nil, err
	}
	var sigEnv jwsEnvelope
	err = json.Unmarshal(encoded, &sigEnv)
	if err != nil {
		return nil, err
	}
	return &sigEnv, nil
}

func getEncodedMessage(signingScheme signature.SigningScheme, isLocal bool, extendedSignedAttribute []signature.Attribute) ([]byte, error) {
	signer, err := getSigner(isLocal, nil, nil)
	if err != nil {
		return nil, err
	}

	signReq, err := getSignReq(signingScheme, signer, extendedSignedAttribute)
	if err != nil {
		return nil, err
	}
	e := envelope{}
	return e.Sign(signReq)
}

func getSignedEnvelope(signingScheme signature.SigningScheme, isLocal bool, extendedSignedAttribute []signature.Attribute) (*jwsEnvelope, error) {
	encoded, err := getEncodedMessage(signingScheme, isLocal, extendedSignedAttribute)
	if err != nil {
		return nil, err
	}
	var env jwsEnvelope
	err = json.Unmarshal(encoded, &env)
	if err != nil {
		return nil, err
	}
	return &env, nil
}

func verifyEnvelope(env *jwsEnvelope) error {
	newEncoded, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, _, err = verifyCore(newEncoded)
	return err
}

func verifyCore(encoded []byte) (*signature.Payload, *signature.SignerInfo, error) {
	env, err := ParseEnvelope(encoded)
	if err != nil {
		return nil, nil, err
	}
	return env.Verify()
}

func TestNewEnvelope(t *testing.T) {
	env := NewEnvelope()
	if env == nil {
		t.Fatal("should get an JWS envelope")
	}
}

// Test the same key exists both in extended signed attributes and protected header
func TestSignFailed(t *testing.T) {
	t.Run("extended attribute conflict with protected header keys", func(t *testing.T) {
		_, err := getEncodedMessage(signature.SigningSchemeX509, true, extSignedAttrRepeated)
		checkErrorEqual(t, `repeated key: "cty" exists in the envelope.`, err.Error())
	})

	t.Run("extended attribute error value", func(t *testing.T) {
		_, err := getEncodedMessage(signature.SigningSchemeX509, true, extSignedAttrErrorValue)
		checkErrorEqual(t, "json: unsupported value: +Inf", err.Error())
	})

	t.Run("unsupported sign algorithm", func(t *testing.T) {
		signer := errorLocalSigner{
			algType: signature.KeyTypeRSA,
			size:    222,
		}
		_, err := getEncodedMessage(signature.SigningSchemeX509, true, nil)
		checkNoError(t, err)

		signReq, err := getSignReq(signature.SigningSchemeX509, &signer, nil)
		checkNoError(t, err)

		e := envelope{}
		_, err = e.Sign(signReq)
		checkErrorEqual(t, `signature algorithm "#0" is not supported`, err.Error())
	})
}

func TestSigningScheme(t *testing.T) {
	var signParams = []struct {
		isLocal       bool
		signingScheme signature.SigningScheme
	}{
		{true, signature.SigningSchemeX509},
		{true, signature.SigningSchemeX509SigningAuthority},
		{false, signature.SigningSchemeX509},
		{false, signature.SigningSchemeX509SigningAuthority},
	}

	for _, tt := range signParams {
		t.Run(fmt.Sprintf("verify_isLocal=%v_signingScheme=%v", tt.isLocal, tt.signingScheme), func(t *testing.T) {
			encoded, err := getEncodedMessage(tt.signingScheme, tt.isLocal, extSignedAttr)
			checkNoError(t, err)

			_, _, err = verifyCore(encoded)
			checkNoError(t, err)
		})
	}
}

func TestSignVerify(t *testing.T) {
	for _, keyType := range signaturetest.KeyTypes {
		for _, size := range signaturetest.GetKeySizes(keyType) {
			t.Run(fmt.Sprintf("%s %d", keyType, size), func(t *testing.T) {
				signer, err := signaturetest.GetTestLocalSigner(keyType, size)
				checkNoError(t, err)

				signReq, err := getSignReq(signature.SigningSchemeX509, signer, nil)
				checkNoError(t, err)

				e := envelope{}
				encoded, err := e.Sign(signReq)
				checkNoError(t, err)

				_, _, err = verifyCore(encoded)
				checkNoError(t, err)
			})
		}
	}
}

func TestVerify(t *testing.T) {
	t.Run("break json format", func(t *testing.T) {
		encoded, err := getEncodedMessage(signature.SigningSchemeX509, true, extSignedAttr)
		checkNoError(t, err)

		encoded[0] = '}'

		_, _, err = verifyCore(encoded)
		checkErrorEqual(t, "invalid character '}' looking for beginning of value", err.Error())
	})

	t.Run("tamper signature", func(t *testing.T) {
		// get envelope
		env, err := getSignedEnvelope(signature.SigningSchemeX509, true, extSignedAttr)
		checkNoError(t, err)

		// temper envelope
		env.Signature = ""

		err = verifyEnvelope(env)
		checkErrorEqual(t, "signature is invalid. Error: crypto/rsa: verification error", err.Error())
	})

	t.Run("empty certificate", func(t *testing.T) {
		// get envelope
		env, err := getSignedEnvelope(signature.SigningSchemeX509, true, extSignedAttr)
		checkNoError(t, err)

		// temper envelope
		env.Header.CertChain = [][]byte{}

		err = verifyEnvelope(env)
		checkErrorEqual(t, "certificate chain is not set", err.Error())
	})

	t.Run("tamper certificate", func(t *testing.T) {
		// get envelope
		env, err := getSignedEnvelope(signature.SigningSchemeX509, true, extSignedAttr)
		checkNoError(t, err)

		// temper envelope
		env.Header.CertChain[0][0] = 'C'

		err = verifyEnvelope(env)
		checkErrorEqual(t, "malformed leaf certificate", err.Error())
	})

	t.Run("malformed protected header base64 encoded", func(t *testing.T) {
		// get envelope
		env, err := getSignedEnvelope(signature.SigningSchemeX509, true, extSignedAttr)
		checkNoError(t, err)

		// temper envelope
		env.Protected = "$" + env.Protected

		err = verifyEnvelope(env)
		checkErrorEqual(t, "jws envelope protected header can't be decoded: illegal base64 data at input byte 0", err.Error())
	})
	t.Run("malformed protected header raw", func(t *testing.T) {
		// get envelope
		env, err := getSignedEnvelope(signature.SigningSchemeX509, true, extSignedAttr)
		checkNoError(t, err)

		// temper envelope
		rawProtected, err := base64.RawURLEncoding.DecodeString(env.Protected)
		checkNoError(t, err)

		rawProtected[0] = '}'
		env.Protected = base64.RawURLEncoding.EncodeToString(rawProtected)

		err = verifyEnvelope(env)
		checkErrorEqual(t, "jws envelope protected header can't be decoded: invalid character '}' looking for beginning of value", err.Error())
	})
}

func TestSignerInfo(t *testing.T) {
	getEnvelopeAndHeader := func(signingScheme signature.SigningScheme) (*jwsEnvelope, *jwsProtectedHeader) {
		// get envelope
		env, err := getSignedEnvelope(signingScheme, true, extSignedAttr)
		checkNoError(t, err)

		// get protected header
		header, err := parseProtectedHeaders(env.Protected)
		checkNoError(t, err)
		return env, header
	}
	updateProtectedHeader := func(env *jwsEnvelope, protected *jwsProtectedHeader) {
		// generate protected header
		headerMap := make(map[string]interface{})
		valueOf := reflect.ValueOf(*protected)
		for i := 0; i < valueOf.NumField(); i++ {
			var key string
			tags := strings.Split(valueOf.Type().Field(i).Tag.Get("json"), ",")
			if len(tags) > 0 {
				key = tags[0]
			}
			if key == "-" {
				continue
			}
			headerMap[key] = valueOf.Field(i).Interface()
		}
		// extract extended attribute
		for key, value := range protected.ExtendedAttributes {
			headerMap[key] = value
		}

		// marshal and write back to envelope
		rawProtected, err := json.Marshal(headerMap)
		checkNoError(t, err)
		env.Protected = base64.RawURLEncoding.EncodeToString(rawProtected)
	}
	getSignerInfo := func(env *jwsEnvelope, protected *jwsProtectedHeader) (*signature.SignerInfo, error) {
		updateProtectedHeader(env, protected)
		// marshal tampered envelope
		newEncoded, err := json.Marshal(env)
		checkNoError(t, err)

		// parse tampered envelope
		newEnv, err := ParseEnvelope(newEncoded)
		checkNoError(t, err)

		return newEnv.SignerInfo()
	}

	t.Run("tamper protected header signing scheme X509", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509)

		// temper protected header
		signingTime := time.Now()
		header.AuthenticSigningTime = &signingTime

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: "io.cncf.notary.authenticSigningTime" header must not be present for notary.x509 signing scheme`, err.Error())
	})

	t.Run("tamper protected header signing scheme X509 Signing Authority", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509SigningAuthority)

		// temper protected header
		signingTime := time.Now()
		header.SigningTime = &signingTime

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: "io.cncf.notary.signingTime" header must not be present for notary.x509.signingAuthority signing scheme`, err.Error())
	})

	t.Run("tamper protected header signing scheme X509 Signing Authority 2", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509SigningAuthority)

		// temper protected header
		header.AuthenticSigningTime = nil

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: "io.cncf.notary.authenticSigningTime" header must be present for notary.x509 signing scheme`, err.Error())
	})

	t.Run("tamper protected header extended attributes", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509)

		// temper protected header
		header.ExtendedAttributes = make(map[string]interface{})

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: "testKey" header is marked critical but not present`, err.Error())
	})

	t.Run("add protected header critical key", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509)

		// temper protected header
		header.Critical = header.Critical[:len(header.Critical)-2]

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: these required headers are not marked as critical: [io.cncf.notary.expiry]`, err.Error())
	})

	t.Run("empty critical section", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509)

		// temper protected header
		header.Critical = []string{}

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: missing "crit" header`, err.Error())
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509)

		// temper protected header
		header.Algorithm = "ES222"

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: signature algorithm "ES222" is not supported`, err.Error())
	})

	t.Run("tamper raw protected header json format", func(t *testing.T) {
		// get envelope
		env, err := getSignedEnvelope(signature.SigningSchemeX509, true, extSignedAttr)
		checkNoError(t, err)

		rawProtected, err := base64.RawURLEncoding.DecodeString(env.Protected)
		checkNoError(t, err)

		// temper envelope
		rawProtected[0] = '}'
		env.Protected = base64.RawURLEncoding.EncodeToString(rawProtected)

		newEncoded, err := json.Marshal(env)
		checkNoError(t, err)

		// parse tampered envelope
		newEnv, err := ParseEnvelope(newEncoded)
		checkNoError(t, err)

		_, err = newEnv.SignerInfo()
		checkErrorEqual(t, "signature envelope format is malformed. error: jws envelope protected header can't be decoded: invalid character '}' looking for beginning of value", err.Error())
	})
	t.Run("tamper signature base64 encoding", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509)

		// temper protected header
		env.Signature = "{" + env.Signature

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: illegal base64 data at input byte 0`, err.Error())
	})
	t.Run("tamper empty signature", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509)

		// temper protected header
		env.Signature = ""

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: cose envelope missing signature`, err.Error())
	})
	t.Run("tamper cert chain", func(t *testing.T) {
		env, header := getEnvelopeAndHeader(signature.SigningSchemeX509)

		// temper protected header
		env.Header.CertChain[0] = append(env.Header.CertChain[0], 'v')

		_, err := getSignerInfo(env, header)
		checkErrorEqual(t, `signature envelope format is malformed. error: x509: trailing data`, err.Error())
	})
}

func TestPayload(t *testing.T) {
	t.Run("tamper envelope cause JWT parse failed", func(t *testing.T) {
		// get envelope
		env, err := getSignedEnvelope(signature.SigningSchemeX509, true, extSignedAttr)
		checkNoError(t, err)

		// tamper payload
		env.Payload = env.Payload[1:]

		// marshal tampered envelope
		newEncoded, err := json.Marshal(env)
		checkNoError(t, err)

		// parse tampered envelope
		newEnv, err := ParseEnvelope(newEncoded)
		checkNoError(t, err)

		_, err = newEnv.Payload()
		checkErrorEqual(t, "payload error: illegal base64 data at input byte 288", err.Error())

	})
}

func TestEmptyEnvelope(t *testing.T) {
	wantErr := &signature.SignatureEnvelopeNotFoundError{}
	env := envelope{}

	t.Run("Verify()_with_empty_envelope", func(t *testing.T) {
		_, _, err := env.Verify()
		if !errors.Is(err, wantErr) {
			t.Fatalf("want: %v, got: %v", wantErr, err)
		}
	})

	t.Run("Payload()_with_empty_envelope", func(t *testing.T) {
		_, err := env.Payload()
		if !errors.Is(err, wantErr) {
			t.Fatalf("want: %v, got: %v", wantErr, err)
		}
	})

	t.Run("SignerInfo()_with_empty_envelope", func(t *testing.T) {
		_, err := env.SignerInfo()
		if !errors.Is(err, wantErr) {
			t.Fatalf("want: %v, got: %v", wantErr, err)
		}
	})
}
