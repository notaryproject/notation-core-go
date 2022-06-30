package signer

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-core-go/internal/testhelper"
)

// Tests various scenarios around newJWSEnvelopeFromBytes method
func TestNewJWSEnvelopeFromBytes(t *testing.T) {
	t.Run("newJWSEnvelopeFromBytes", func(t *testing.T) {
		if _, err := newJWSEnvelopeFromBytes([]byte(TestValidSig)); err != nil {
			t.Errorf("Error found: %q", err)
		}
	})

	t.Run("newJWSEnvelopeFromBytes Error", func(t *testing.T) {
		if _, err := newJWSEnvelopeFromBytes([]byte("Malformed")); err == nil {
			t.Errorf("Expected error but not found")
		}
	})
}

// Tests various scenarios around validateIntegrity method
func TestValidateIntegrity(t *testing.T) {
	t.Run("with newJWSEnvelope() returns error", func(t *testing.T) {
		env := jwsEnvelope{}
		err := env.validateIntegrity()
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("Expected SignatureNotFoundError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with NewJWSEnvelopeFromBytes works", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte(TestValidSig))
		err := env.validateIntegrity()
		if err != nil {
			t.Errorf("validateIntegrity(). Error = %s", err)
		}
	})

	t.Run("with invalid base64 bytes sig envelope returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"Hi!\",\"Protected\":\"Hi\",\"Header\":{},\"Signature\":\"Hi!\"}"))
		err := env.validateIntegrity()
		if !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with incomplete sig envelope returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJhbGciOiJQUzI1NiIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiXSwiaW8uY25jZi5ub3Rhcnkuc2luaW5nVGltZSI6IjIwMDYtMDEtMDJUMTU6MDQ6MDVaIn0\",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if err := env.validateIntegrity(); !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with tempered payload returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte(TestTamperedSig))
		if err := env.validateIntegrity(); !(err != nil && errors.As(err, new(SignatureIntegrityError))) {
			t.Errorf("Expected SignatureIntegrityError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with tempered certificate returns error", func(t *testing.T) {
		var jwsInternal jwsInternalEnvelope
		json.Unmarshal([]byte(TestValidSig), &jwsInternal)
		jwsInternal.Header.CertChain[0] = testhelper.GetRSALeafCertificate().Cert.Raw
		tempered, _ := json.Marshal(jwsInternal)
		env, _ := newJWSEnvelopeFromBytes(tempered)
		if err := env.validateIntegrity(); !(err != nil && errors.As(err, new(SignatureIntegrityError))) {
			t.Errorf("Expected SignatureIntegrityError but found %q", reflect.TypeOf(err))
		}
	})
}

// Tests various scenarios around getSignerInfo method
func TestGetSignerInfo(t *testing.T) {
	t.Run("with newJWSEnvelope before sign returns error", func(t *testing.T) {
		env := jwsEnvelope{}
		_, err := env.getSignerInfo()
		if !(err != nil && errors.As(err, new(SignatureNotFoundError))) {
			t.Errorf("Expected SignatureNotFoundError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with newJWSEnvelope after sign works", func(t *testing.T) {
		env := jwsEnvelope{}
		env.signPayload(getSignRequest())
		_, err := env.getSignerInfo()
		if err != nil {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})

	t.Run("with NewJWSEnvelopeFromBytes works", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte(TestValidSig))
		_, err := env.getSignerInfo()
		if err != nil {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})

	t.Run("with invalid base64 bytes sig envelope returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"Hi!\",\"Protected\":\"Hi\",\"Header\":{},\"Signature\":\"Hi!\"}"))
		if _, err := env.getSignerInfo(); err == nil {
			t.Errorf("Expected error but not found")
		}
	})

	t.Run("with invalid singing time returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJhbGciOiJQUzI1NiIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiXSwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiOiIyMDA2LS0wMlQxNTowNDowNVoifQ\"" +
			",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if _, err := env.getSignerInfo(); !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with missing crit header returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6Im9sYWYiLCJhdWQiOiJhdWRyZXkiLCJpYXQiOjE2NTQ1ODYyODIsImV4cCI6MTY1NDU4Njg4Mn0\"" +
			",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if _, err := env.getSignerInfo(); !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with malformed alg header returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJhbGciOjEzLCJjcml0IjpbImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIl0sImlvLmNuY2Yubm90YXJ5LnNpbmluZ1RpbWUiOiIyMDA2LTAxLTAyVDE1OjA0OjA1WiJ9\"" +
			",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if _, err := env.getSignerInfo(); !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with malformed cty header returns error", func(t *testing.T) {
		env, _ := newJWSEnvelopeFromBytes([]byte("{\"Payload\":\"eyJhbGciOiJIUzI1NiJ9\",\"Protected\":\"eyJhbGciOiJQUzUxMiIsImN0eSI6MTIzLCJjcml0IjpbImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdUaW1lIl0sImlvLmNuY2Yubm90YXJ5LnNpbmluZ1RpbWUiOiIyMDA2LTAxLTAyVDE1OjA0OjA1WiJ9\"" +
			",\"Header\":{},\"Signature\":\"YjGj\"}"))
		if _, err := env.getSignerInfo(); !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})
}

// Tests various scenarios around signPayload method
func TestSignPayload(t *testing.T) {
	env := jwsEnvelope{}
	t.Run("using rsa key with newJWSEnvelope works", func(t *testing.T) {
		req := getSignRequest()
		_, err := env.signPayload(req)
		if err != nil {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})

	t.Run("using ec key  with newJWSEnvelope works", func(t *testing.T) {
		req := getSignRequest()
		req.CertificateChain = []*x509.Certificate{testhelper.GetECLeafCertificate().Cert, testhelper.GetECRootCertificate().Cert}
		_, err := env.signPayload(req)
		if err != nil {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})

	t.Run("with unsupported certificate returns error", func(t *testing.T) {
		req := getSignRequest()
		req.CertificateChain = []*x509.Certificate{testhelper.GetUnsupportedCertificate().Cert}
		if _, err := env.signPayload(req); !(err != nil && errors.As(err, new(UnsupportedSigningKeyError))) {
			t.Errorf("Expected UnsupportedSigningKeyError but found %q", err)
		}
	})
}
