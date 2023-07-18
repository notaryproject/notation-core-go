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

package jws

import (
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
)

type errorLocalSigner struct {
	algType      signature.KeyType
	size         int
	keySpecError error
}

// Sign returns error
func (s *errorLocalSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	return nil, nil, errors.New("sign error")
}

// KeySpec returns the key specification.
func (s *errorLocalSigner) KeySpec() (signature.KeySpec, error) {
	return signature.KeySpec{
		Type: s.algType,
		Size: s.size,
	}, s.keySpecError
}

// PrivateKey returns nil.
func (s *errorLocalSigner) PrivateKey() crypto.PrivateKey {
	return nil
}

// CertificateChain returns nil.
func (s *errorLocalSigner) CertificateChain() ([]*x509.Certificate, error) {
	return nil, nil
}

func Test_remoteSigningMethod_Verify(t *testing.T) {
	s := &remoteSigningMethod{} // Sign signs the payload and returns the raw signature and certificates.
	err := s.Verify("", "", nil)
	if err == nil {
		t.Fatalf("should panic")
	}
}

func Test_newLocalSigningMethod(t *testing.T) {
	signer := errorLocalSigner{}
	_, err := newLocalSigningMethod(&signer)
	checkErrorEqual(t, `signature algorithm "#0" is not supported`, err.Error())
}

func Test_newRemoteSigningMethod(t *testing.T) {
	_, err := newRemoteSigningMethod(&errorLocalSigner{})
	checkErrorEqual(t, `signature algorithm "#0" is not supported`, err.Error())
}

func Test_remoteSigningMethod_CertificateChain(t *testing.T) {
	certs := []*x509.Certificate{
		testhelper.GetRSALeafCertificate().Cert,
	}

	signer, err := getSigner(false, certs, testhelper.GetRSALeafCertificate().PrivateKey)
	checkNoError(t, err)

	signingScheme, err := newRemoteSigningMethod(signer)
	checkNoError(t, err)

	_, err = signingScheme.CertificateChain()
	checkErrorEqual(t, "certificate chain is not set", err.Error())
}

func Test_remoteSigningMethod_Sign(t *testing.T) {
	signer := errorLocalSigner{
		algType:      signature.KeyTypeRSA,
		size:         2048,
		keySpecError: nil,
	}
	signingScheme, err := newRemoteSigningMethod(&signer)
	checkNoError(t, err)

	_, err = signingScheme.Sign("", nil)
	checkErrorEqual(t, "sign error", err.Error())
}
func Test_extractJwtAlgorithm(t *testing.T) {
	_, err := extractJwtAlgorithm(&errorLocalSigner{})
	checkErrorEqual(t, `signature algorithm "#0" is not supported`, err.Error())

	_, err = extractJwtAlgorithm(&errorLocalSigner{
		keySpecError: errors.New("get key spec error"),
	})
	checkErrorEqual(t, `get key spec error`, err.Error())
}

func Test_verifyJWT(t *testing.T) {
	type args struct {
		tokenString string
		publicKey   interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "invalid signature",
			args: args{
				tokenString: "eyJhbGciOiJQUzM4NCIsImNyaXQiOlsiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSIsInRlc3RLZXkiLCJpby5jbmNmLm5vdGFyeS5leHBpcnkiXSwiY3R5IjoiYXBwbGljYXRpb24vdm5kLmNuY2Yubm90YXJ5LnBheWxvYWQudjEranNvbiIsImlvLmNuY2Yubm90YXJ5LmV4cGlyeSI6IjIwMjItMDgtMjRUMTc6MTg6MTUuNDkxNzQ1ODQ1KzA4OjAwIiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1NjaGVtZSI6Im5vdGFyeS54NTA5IiwiaW8uY25jZi5ub3Rhcnkuc2lnbmluZ1RpbWUiOiIyMDIyLTA4LTI0VDE2OjE4OjE1LjQ5MTc0NTgwNCswODowMCIsInRlc3RLZXkiOiJ0ZXN0VmFsdWUiLCJ0ZXN0S2V5MiI6InRlc3RWYWx1ZTIifQ.ImV3b2dJQ0p6ZFdKcVpXTjBJam9nZXdvZ0lDQWdJbTFsWkdsaFZIbHdaU0k2SUNKaGNIQnNhV05oZEdsdmJpOTJibVF1YjJOcExtbHRZV2RsTG0xaGJtbG1aWE4wTG5ZeEsycHpiMjRpTEFvZ0lDQWdJbVJwWjJWemRDSTZJQ0p6YUdFeU5UWTZOek5qT0RBek9UTXdaV0V6WW1FeFpUVTBZbU15TldNeVltUmpOVE5sWkdRd01qZzBZell5WldRMk5URm1aVGRpTURBek5qbGtZVFV4T1dFell6TXpNeUlzQ2lBZ0lDQWljMmw2WlNJNklERTJOekkwTEFvZ0lDQWdJbUZ1Ym05MFlYUnBiMjV6SWpvZ2V3b2dJQ0FnSUNBZ0lDSnBieTUzWVdKaWFYUXRibVYwZDI5eWEzTXVZblZwYkdSSlpDSTZJQ0l4TWpNaUNpQWdJQ0I5Q2lBZ2ZRcDlDZ2s9Ig.YmF1_5dMW4YWK2fzct1dp25lTy8p0qdSmR-O2fZsf29ohiLYGUVXfvRjEgERzZvDd49aOYQvrEgGvoU9FfK2KIqHrJ8kliI00wd4kuK57aE83pszBMOOrZqAjqkdyoj7dswmwJSyjMC9fhwh_AwrrOnrBjw4U0vGTrImMQEwHfVq0MWLCuw9YpFkytLPeCl8n825EtqMzwYYTUzdQfQJO_ZZrS34n8tK0IRZrX2LjrYz9HqR_UFgVqf_G9qwJpekYyd9Aacl9y4x7zzI-R-bADFgztyAYeWRmE75qI26OgG-ss4wfG-ZbchEm6FYU8py64bsLmJtK9muPd9ZU7SXQOEVzxtXoQFnUhT9AgaNNoxnSnU25mMjAeuGDj0Xn_Gv7f24PyDk9ZEE3WjrguJyzaP6P4jYugXr6Afq10HXRpI_cE8B-6USGpiRH9iJLE04xumWpjWup9p5fv3Fnt3Au1dhbgaDvrSGMHmmCSW4dk7_87Q4LGkGcbn0zNINydcg",
				publicKey:   testhelper.GetRSALeafCertificate().Cert.PublicKey,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyJWT(tt.args.tokenString, tt.args.publicKey); (err != nil) != tt.wantErr {
				t.Errorf("verifyJWT() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
