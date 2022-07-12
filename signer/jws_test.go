package signer

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-core-go/testhelper"
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

	t.Run("with missing crit header works", func(t *testing.T) {
		sig := "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLm1hbmlmZXN0LnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsInNpemUiOjE2NzI0LCJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9fX0\"," +
			"\"protected\":\"eyJhbGciOiJQUzM4NCIsImN0eSI6ImFwcGxpY2F0aW9uL3ZuZC5jbmNmLm5vdGFyeS52Mi5qd3MudjEiLCJpby5jbmNmLm5vdGFyeS5zaWduaW5nVGltZSI6IjIwMjItMDctMDZUMjA6MjU6NDYtMDc6MDAifQ\"," +
			"\"header\":{" +
			"\"x5c\":[" +
			"\"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\"]}," +
			"\"signature\":\"jmobgyxycStcafuQ6_2RIixMUNH5CCm_AgnoITqrFFDgLbIx3ItMFoQCs7YRhtwdu5B_OQF5tQ_ZWAu4EFJ_yJelpNqxJLM4S5dyprZ0_s5i_FyBsDQ91SV-pS8gdhIeCUfbE7CwsY1JxisHk8YlK-dPvtOAzEfGlyIR80tQ6YB9nuK6QQSjmmRH8e4p5j_HpvddizLZJRXgna2b3ijHGOzdXlvimdFbVKKZE7fO-WYJVpGqkU-WCUARioo-j95coaLtBbk0b3I85JqEpVupzujGeViosG6-qcPOnO-d9izAQn6TtR6hqMDHqvYDvbCFXOBcWn7pSHH-9pS4q8-xAf6BqOPfgUH9n-na2e0X5vYHCaAKkWzKzEXnimBlPJh7LPjr-nm4_vjrY5Sj8ZEa_J6keKwZENPCQ-BqZBPrQbEbw9qdaOLYEsZl8FWTK-jTOVmpw1sXWYh3WzYh1HzPcqVcdAFk0LluwXVxde1By1cMxZ3xlKj7j7zKqkCWaQJB\"}\n"
		env, _ := newJWSEnvelopeFromBytes([]byte(sig))
		if err := env.validateIntegrity(); err != nil {
			t.Errorf("validateIntegrity(). Error: %s", err.Error())
		}

		if _, err := env.getSignerInfo(); err != nil {
			t.Errorf("validateIntegrity(). Error: %s", err.Error())
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
		certs := []*x509.Certificate{testhelper.GetECLeafCertificate().Cert, testhelper.GetECRootCertificate().Cert}
		req := getSignRequest()
		req.SignatureProvider, _ = NewLocalSignatureProvider(certs, testhelper.GetECLeafCertificate().PrivateKey)
		_, err := env.signPayload(req)
		if err != nil {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})
}
