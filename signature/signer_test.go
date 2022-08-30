package signature

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestNewLocalSigner(t *testing.T) {
	tests := []struct {
		name      string
		certs     []*x509.Certificate
		key       crypto.PrivateKey
		expect    LocalSigner
		expectErr bool
	}{
		{
			name:      "empty certs",
			certs:     make([]*x509.Certificate, 0),
			key:       nil,
			expect:    nil,
			expectErr: true,
		},
		{
			name: "unsupported leaf cert",
			certs: []*x509.Certificate{
				{PublicKey: ed25519.PublicKey{}},
			},
			key:       nil,
			expect:    nil,
			expectErr: true,
		},
		{
			name: "keys not match",
			certs: []*x509.Certificate{
				testhelper.GetECLeafCertificate().Cert,
			},
			key:       testhelper.GetRSARootCertificate().PrivateKey,
			expect:    nil,
			expectErr: true,
		},
		{
			name: "keys not match",
			certs: []*x509.Certificate{
				testhelper.GetRSARootCertificate().Cert,
			},
			key:       testhelper.GetECLeafCertificate().PrivateKey,
			expect:    nil,
			expectErr: true,
		},
		{
			name: "RSA keys match",
			certs: []*x509.Certificate{
				testhelper.GetRSALeafCertificate().Cert,
			},
			key: testhelper.GetRSALeafCertificate().PrivateKey,
			expect: &localSigner{
				keySpec: KeySpec{
					Type: KeyTypeRSA,
					Size: 3072,
				},
				key: testhelper.GetRSALeafCertificate().PrivateKey,
				certs: []*x509.Certificate{
					testhelper.GetRSALeafCertificate().Cert,
				},
			},
			expectErr: false,
		},
		{
			name: "EC keys match",
			certs: []*x509.Certificate{
				testhelper.GetECLeafCertificate().Cert,
			},
			key: testhelper.GetECLeafCertificate().PrivateKey,
			expect: &localSigner{
				keySpec: KeySpec{
					Type: KeyTypeEC,
					Size: 384,
				},
				key: testhelper.GetECLeafCertificate().PrivateKey,
				certs: []*x509.Certificate{
					testhelper.GetECLeafCertificate().Cert,
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewLocalSigner(tt.certs, tt.key)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(signer, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, signer)
			}
		})
	}
}

func TestSign(t *testing.T) {
	signer := &localSigner{}

	raw, certs, err := signer.Sign(make([]byte, 0))
	if err == nil {
		t.Errorf("expect error but got nil")
	}
	if raw != nil {
		t.Errorf("expect nil raw signature but got %v", raw)
	}
	if certs != nil {
		t.Errorf("expect nil certs but got %v", certs)
	}
}

func TestKeySpec(t *testing.T) {
	expectKeySpec := KeySpec{
		Type: KeyTypeRSA,
		Size: 256,
	}
	signer := &localSigner{keySpec: expectKeySpec}

	keySpec, err := signer.KeySpec()

	if err != nil {
		t.Errorf("expect no error but got %v", err)
	}
	if !reflect.DeepEqual(keySpec, expectKeySpec) {
		t.Errorf("expect keySpec %+v, got %+v", expectKeySpec, keySpec)
	}
}

func TestCertificateChain(t *testing.T) {
	expectCerts := []*x509.Certificate{
		testhelper.GetRSALeafCertificate().Cert,
	}
	signer := &localSigner{certs: expectCerts}

	certs, err := signer.CertificateChain()

	if err != nil {
		t.Errorf("expect no error but got %v", err)
	}
	if !reflect.DeepEqual(certs, expectCerts) {
		t.Errorf("expect certs %+v, got %+v", expectCerts, certs)
	}
}

func TestPrivateKey(t *testing.T) {
	expectKey := testhelper.GetRSALeafCertificate().PrivateKey
	signer := &localSigner{key: expectKey}

	key := signer.PrivateKey()

	if !reflect.DeepEqual(key, expectKey) {
		t.Errorf("expect key %+v, got %+v", expectKey, key)
	}
}

func TestVerifyAuthenticity(t *testing.T) {
	tests := []struct {
		name       string
		signerInfo *SignerInfo
		certs      []*x509.Certificate
		expect     *x509.Certificate
		expectErr  bool
	}{
		{
			name:       "empty certs",
			signerInfo: nil,
			certs:      make([]*x509.Certificate, 0),
			expect:     nil,
			expectErr:  true,
		},
		{
			name:       "nil signerInfo",
			signerInfo: nil,
			certs: []*x509.Certificate{
				testhelper.GetECLeafCertificate().Cert,
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name:       "no cert matches",
			signerInfo: &SignerInfo{},
			certs: []*x509.Certificate{
				testhelper.GetECLeafCertificate().Cert,
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "cert matches",
			signerInfo: &SignerInfo{
				CertificateChain: []*x509.Certificate{
					testhelper.GetECLeafCertificate().Cert,
				},
			},
			certs: []*x509.Certificate{
				testhelper.GetECLeafCertificate().Cert,
			},
			expect:    testhelper.GetECLeafCertificate().Cert,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := VerifyAuthenticity(tt.signerInfo, tt.certs)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(cert, tt.expect) {
				t.Errorf("expect cert %+v, got %+v", tt.expect, cert)
			}
		})
	}
}
