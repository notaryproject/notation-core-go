package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
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

	t.Run("with wrong certificate returns error", func(t *testing.T) {
		var jwsInternal jwsInternalEnvelope
		json.Unmarshal([]byte(TestValidSig), &jwsInternal)
		jwsInternal.Header.CertChain[0] = testhelper.GetRSALeafCertificate().Cert.Raw
		tempered, _ := json.Marshal(jwsInternal)
		env, _ := newJWSEnvelopeFromBytes(tempered)
		if err := env.validateIntegrity(); !(err != nil && errors.As(err, new(SignatureIntegrityError))) {
			t.Errorf("Expected SignatureIntegrityError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with invalid certificate returns error", func(t *testing.T) {
		malformedSig := "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLm1hbmlmZXN0LnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsInNpemUiOjE2NzI0LCJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9fX0\",\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSIsInNpZ25lZENyaXRLZXkxIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luIiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luTWluVmVyc2lvbiJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkucGF5bG9hZC52MStqc29uIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IjoiMjAyMi0wOC0wNlQxMDowNTowNy0wNzowMCIsImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdTY2hlbWUiOiJub3RhcnkueDUwOS5zaWduaW5nQXV0aG9yaXR5IiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiOiIyMDIyLTA4LTA1VDEwOjA1OjA3LTA3OjAwIiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luIjoiSG9sYSBQbHVnaW4iLCJpby5jbmNmLm5vdGFyeS52ZXJpZmljYXRpb25QbHVnaW5NaW5WZXJzaW9uIjoiMS4xLjEiLCJzaWduZWRDcml0S2V5MSI6InNpZ25lZFZhbHVlMSIsInNpZ25lZEtleTEiOiJzaWduZWRLZXkyIn0\",\"header\":{\"x5c\":[\"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\"],\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"},\"signature\":\"K5r5b2bJF15kV2Qe5NXf42SCI5_V9K0sCuHSd1bg2OFIOp3FcupjYT4yb26jsV2aE9lrsn8FNxoP-PqkV385klZ_xnTzhRO0T3S7bCL_wu2ZtzuRKp43yOjPc7TPdbd2Q1BKd5rIS05RtxfZTYF1gGIWyRMMc8pos-EgBGhlEXNK78IsH7Eh__bk6pFlY0y5TsKDx8-9h85OKL910CKtCyjP3JgLmB_STxc6iz7iSC8lBmiq_fra3lhfwgDTwTWL2I82-SNFGf3baANppjLP-W1f6ckV9PaFmbPz8hMZ_kYXMRk100IkeSz5inK8rfbCFPHeA6evjydPNO35noIY1ETy7AppB8HlctY903u_iRGh4ur4mKf4snduQbpDr9EARG0c_6styaiwhxkshkrHLKov0C_ZZPNqAZ5ItN2QuBShyNtaKzWPCPjF4EPANVnFjdEH8Up4WpShMX3-N1wQb3IQmNf9kU04YFwkTJn8HECFseGRmZAvG8x0W5PcQik5\"}"

		env, _ := newJWSEnvelopeFromBytes([]byte(malformedSig))
		if err := env.validateIntegrity(); !(err != nil && errors.As(err, new(MalformedSignatureError))) {
			t.Errorf("validateIntegrity(). Expected SignatureIntegrityError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("with malformed signature returns error", func(t *testing.T) {
		x509WithAuthSigningTime := "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLm1hbmlmZXN0LnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsInNpemUiOjE2NzI0LCJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9fX0\",\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSIsInNpZ25lZENyaXRLZXkxIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luIiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luTWluVmVyc2lvbiJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkucGF5bG9hZC52MStqc29uIiwiaW8uY25jZi5ub3RhcnkuYXV0aGVudGljU2lnbmluZ1RpbWUiOiIyMDIyLTA4LTA1VDEwOjAwOjQ2LTA3OjAwIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IjoiMjAyMi0wOC0wNlQxMDowMDo0Ni0wNzowMCIsImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdTY2hlbWUiOiJub3RhcnkueDUwOSIsImlvLmNuY2Yubm90YXJ5LnZlcmlmaWNhdGlvblBsdWdpbiI6IkhvbGEgUGx1Z2luIiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luTWluVmVyc2lvbiI6IjEuMS4xIiwic2lnbmVkQ3JpdEtleTEiOiJzaWduZWRWYWx1ZTEiLCJzaWduZWRLZXkxIjoic2lnbmVkS2V5MiJ9\",\"header\":{\"x5c\":[\"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\"],\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"},\"signature\":\"sopnDN-hfcaBXChHwGBAK6nmkDYazYgs8dxeb6jD9zWLVd5sE0Vzzv5LDlk0fHTGrufVPw4xx_Y3m1qFBxUMONJqj0ROb7vE--HLcNTPdGgRu7CeuE7D_SCxqTKF0PmzwXbibr2PNJpQ_aS4bBwrG6amjk2GuxNy8v-GCRVFQy_DcwGtDfjjbN_wdwlsxyCGX7PL8Vh97-H4xHabpVKKGIV4FNC0a_3vTeAsuwcOxwXTIs5SLFQ1EHTW2cSI9auv11qBo6HSVZtd7_cRoMKJDnS26eQ_nkz-FaxMh3uyxXFiXf3TlNrZeEOERmAinUr8dwp3TSGcZRJeJPqIa5Zfvk1F9VapwHJkN87UiLlKnspgF2X1HMYELCLL15ntPYJme0EbOo2blQ4Iqo1oMzln92L4TPqqmuDT9uWpDGzuzSc1Gb5K6SGrsVzbqO3ECKoPA_YGHYelZ_YXK0EVSUM9rV0VWkVeMYi5KiQDErTEXm7Rh01XSAUMpe0zxJaQ0-vm\"}"
		x509SaWithSigningTime := "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLm1hbmlmZXN0LnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsInNpemUiOjE2NzI0LCJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9fX0\",\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSIsInNpZ25lZENyaXRLZXkxIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luIiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luTWluVmVyc2lvbiJdLCJjdHkiOiJhcHBsaWNhdGlvbi92bmQuY25jZi5ub3RhcnkucGF5bG9hZC52MStqc29uIiwiaW8uY25jZi5ub3RhcnkuZXhwaXJ5IjoiMjAyMi0wOC0wNlQxMDowNTowNy0wNzowMCIsImlvLmNuY2Yubm90YXJ5LnNpZ25pbmdTY2hlbWUiOiJub3RhcnkueDUwOS5zaWduaW5nQXV0aG9yaXR5IiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiOiIyMDIyLTA4LTA1VDEwOjA1OjA3LTA3OjAwIiwiaW8uY25jZi5ub3RhcnkudmVyaWZpY2F0aW9uUGx1Z2luIjoiSG9sYSBQbHVnaW4iLCJpby5jbmNmLm5vdGFyeS52ZXJpZmljYXRpb25QbHVnaW5NaW5WZXJzaW9uIjoiMS4xLjEiLCJzaWduZWRDcml0S2V5MSI6InNpZ25lZFZhbHVlMSIsInNpZ25lZEtleTEiOiJzaWduZWRLZXkyIn0\",\"header\":{\"x5c\":[\"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\"],\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"},\"signature\":\"K5r5b2bJF15kV2Qe5NXf42SCI5_V9K0sCuHSd1bg2OFIOp3FcupjYT4yb26jsV2aE9lrsn8FNxoP-PqkV385klZ_xnTzhRO0T3S7bCL_wu2ZtzuRKp43yOjPc7TPdbd2Q1BKd5rIS05RtxfZTYF1gGIWyRMMc8pos-EgBGhlEXNK78IsH7Eh__bk6pFlY0y5TsKDx8-9h85OKL910CKtCyjP3JgLmB_STxc6iz7iSC8lBmiq_fra3lhfwgDTwTWL2I82-SNFGf3baANppjLP-W1f6ckV9PaFmbPz8hMZ_kYXMRk100IkeSz5inK8rfbCFPHeA6evjydPNO35noIY1ETy7AppB8HlctY903u_iRGh4ur4mKf4snduQbpDr9EARG0c_6styaiwhxkshkrHLKov0C_ZZPNqAZ5ItN2QuBShyNtaKzWPCPjF4EPANVnFjdEH8Up4WpShMX3-N1wQb3IQmNf9kU04YFwkTJn8HECFseGRmZAvG8x0W5PcQik5\"}"
		x509SaMissingSigningTime := "{\"payload\":\"eyJ0YXJnZXRBcnRpZmFjdCI6eyJtZWRpYVR5cGUiOiJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLm1hbmlmZXN0LnYxK2pzb24iLCJkaWdlc3QiOiJzaGEyNTY6NzNjODAzOTMwZWEzYmExZTU0YmMyNWMyYmRjNTNlZGQwMjg0YzYyZWQ2NTFmZTdiMDAzNjlkYTUxOWEzYzMzMyIsInNpemUiOjE2NzI0LCJhbm5vdGF0aW9ucyI6eyJpby53YWJiaXQtbmV0d29ya3MuYnVpbGRJZCI6IjEyMyJ9fX0\",\"protected\":\"eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSIsInNpZ25lZENyaXRLZXkxIiwiaW8uY25jZi5ub3RhcnkuYXV0aGVudGljU2lnbmluZ1RpbWUiLCJpby5jbmNmLm5vdGFyeS5leHBpcnkiLCJpby5jbmNmLm5vdGFyeS52ZXJpZmljYXRpb25QbHVnaW4iLCJpby5jbmNmLm5vdGFyeS52ZXJpZmljYXRpb25QbHVnaW5NaW5WZXJzaW9uIl0sImN0eSI6ImFwcGxpY2F0aW9uL3ZuZC5jbmNmLm5vdGFyeS5wYXlsb2FkLnYxK2pzb24iLCJpby5jbmNmLm5vdGFyeS5leHBpcnkiOiIyMDIyLTA4LTA2VDIwOjAyOjU2LTA3OjAwIiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSI6Im5vdGFyeS54NTA5LnNpZ25pbmdBdXRob3JpdHkiLCJpby5jbmNmLm5vdGFyeS52ZXJpZmljYXRpb25QbHVnaW4iOiJIb2xhIFBsdWdpbiIsImlvLmNuY2Yubm90YXJ5LnZlcmlmaWNhdGlvblBsdWdpbk1pblZlcnNpb24iOiIxLjEuMSIsInNpZ25lZENyaXRLZXkxIjoic2lnbmVkVmFsdWUxIiwic2lnbmVkS2V5MSI6InNpZ25lZEtleTIifQ\",\"header\":{\"x5c\":[\"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\"],\"io.cncf.notary.SigningAgent\":\"NotationUnitTest/1.0.0\"},\"signature\":\"AXGzB9wvKlrF7urv9qcFDluz4obIbZa53cPrjc4BzheRNojex6oHMbhBpoGYGQtzzE1sTHa4JeF5hGMBi14s1HAH4vpWWTWbLMwwzcDhCmjuAJBMkuZ5JPZ-vq86v6r8di4IKJGncNC53E8VqMHwbCO32Z7v3af7jlQWpRDcWPImkI1HM1NZtiHv7V5JdGGwHsBN8s_u-xrAK_gZytf1QfVmuRl34mU3N-sHjk00pxdyAzknDfc21-MDBk-waQ4BONFuF6h7VxCSvz7uckj2GOAiVJYKe_0ek6bfkzFIXMDHlMUlBzlLmxiGqa7D9GSdreKVDdoPdiizDXJmWKRP8UFSwkvYPHmnu8AoFTkZZjFbkQEsUnQerHJsXIBAndq3BzsD84xVygv5IrcX3VQY8hSi55tjuf7spi5Bkrqbcj_NtwowX_mGLQXA6SOdBPkd4UXo47bzwXRccU2CRhiwbig46eak6ZRVpiPWzyWL1dwuKSH6gRq5zJpH5QojotHz\"}\n"
		for _, sig := range []string{x509WithAuthSigningTime, x509SaWithSigningTime, x509SaMissingSigningTime} {
			env, _ := newJWSEnvelopeFromBytes([]byte(sig))
			if err := env.validateIntegrity(); err != nil {
				t.Errorf("validateIntegrity(). Error = %s", err)
			}

			if _, err := env.getSignerInfo(); !(err != nil && errors.As(err, new(MalformedSignatureError))) {
				t.Errorf("getSignerInfo. Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
			}
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

	t.Run("using ec key with newJWSEnvelope works", func(t *testing.T) {
		certs := []*x509.Certificate{testhelper.GetECLeafCertificate().Cert, testhelper.GetECRootCertificate().Cert}
		req := getSignRequest()
		req.SignatureProvider, _ = NewLocalSignatureProvider(certs, testhelper.GetECLeafCertificate().PrivateKey)
		_, err := env.signPayload(req)
		if err != nil {
			t.Errorf("getSignerInfo(). Error = %s", err)
		}
	})
}

func TestSignPayloadError(t *testing.T) {
	env := jwsEnvelope{}
	req := getSignRequest()
	t.Run("when SignatureProvider'KeySpec returns error", func(t *testing.T) {
		req.SignatureProvider = ErrorSignatureProvider{KeySpecError: true}
		if _, err := env.signPayload(req); !(err != nil && errors.As(err, new(MalformedSignRequestError))) {
			t.Errorf("signPayload(). Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("when SignatureProvider'SignError returns error", func(t *testing.T) {
		req.SignatureProvider = ErrorSignatureProvider{SignError: true}
		if _, err := env.signPayload(req); !(err != nil && errors.As(err, new(MalformedSignRequestError))) {
			t.Errorf("signPayload(). Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("when SignatureProvider'Sign returns invalid certificate chain", func(t *testing.T) {
		req.SignatureProvider = ErrorSignatureProvider{InvalidCertChain: true}
		if _, err := env.signPayload(req); !(err != nil && errors.As(err, new(MalformedSignRequestError))) {
			t.Errorf("signPayload(). Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})

	t.Run("when SignatureProvider'KeySpec returns invalid value", func(t *testing.T) {
		req.SignatureProvider = ErrorSignatureProvider{InvalidKeySpec: true}
		if _, err := env.signPayload(req); !(err != nil && errors.As(err, new(SignatureAlgoNotSupportedError))) {
			t.Errorf("signPayload(). Expected MalformedSignatureError but found %q", reflect.TypeOf(err))
		}
	})
}

type ErrorSignatureProvider struct {
	KeySpecError     bool
	SignError        bool
	InvalidCertChain bool
	InvalidKeySpec   bool
}

func (sp ErrorSignatureProvider) KeySpec() (KeySpec, error) {
	if sp.KeySpecError {
		return RSA_2048, fmt.Errorf("intentional KeySpec() error")
	}

	if sp.InvalidKeySpec {
		return "", nil
	}
	return RSA_2048, nil
}

func (sp ErrorSignatureProvider) Sign(bytes []byte) ([]byte, []*x509.Certificate, error) {
	if sp.SignError {
		return nil, nil, fmt.Errorf("intentional Sign() error")
	}

	rsaRoot := testhelper.GetRSARootCertificate()
	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	certTuple := testhelper.GetRSACertTupleWithPK(pk, "TestSignPayloadError_"+strconv.Itoa(pk.Size()), &rsaRoot)
	if sp.InvalidCertChain {
		lsp, _ := NewLocalSignatureProvider([]*x509.Certificate{certTuple.Cert, testhelper.GetECRootCertificate().Cert}, pk)
		return lsp.Sign(bytes)
	}

	lsp, _ := NewLocalSignatureProvider([]*x509.Certificate{certTuple.Cert, rsaRoot.Cert}, pk)
	return lsp.Sign(bytes)
}
