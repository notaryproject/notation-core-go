package base

import (
	"crypto/x509"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
)

var (
	errMsg              = "error msg"
	invalidSigningAgent = "test/1"
	validSigningAgent   = "test/0"
	invalidContentType  = "text/plain"
	validContentType    = "application/vnd.cncf.notary.payload.v1+json"
	validContent        = "test content"
	validBytes          = []byte(validContent)
	time08_02           time.Time
	time08_03           time.Time
	timeLayout          = "2006-01-02"
	signiningSchema = signature.SigningScheme("notary.x509")
	validSignerInfo     = &signature.SignerInfo{
		Signature:          validBytes,
		SignatureAlgorithm: signature.AlgorithmPS384,
		SignedAttributes: signature.SignedAttributes{
			SigningTime: testhelper.GetRSALeafCertificate().Cert.NotBefore,
			Expiry:      testhelper.GetECLeafCertificate().Cert.NotAfter,
			SigningScheme: signiningSchema,
		},
		CertificateChain: []*x509.Certificate{
			testhelper.GetRSALeafCertificate().Cert,
			testhelper.GetRSARootCertificate().Cert,
		},
	}
	validPayload = &signature.Payload{
		ContentType: validContentType,
		Content:     validBytes,
	}
	validEnvelopeContent = &signature.EnvelopeContent{
		SignerInfo: *validSignerInfo,
		Payload:    *validPayload,
	}
	validReq = &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: validContentType,
			Content:     validBytes,
		},
		SigningTime: testhelper.GetRSALeafCertificate().Cert.NotBefore,
		Expiry:      testhelper.GetRSALeafCertificate().Cert.NotAfter,
		SigningScheme: signiningSchema,
		Signer: &mockSigner{
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			certs: []*x509.Certificate{
				testhelper.GetRSALeafCertificate().Cert,
				testhelper.GetRSARootCertificate().Cert,
			},
		},
		SigningAgent: validSigningAgent,
	}
	signReq1 = &signature.SignRequest{
		Payload: signature.Payload{
			ContentType: validContentType,
			Content:     validBytes,
		},
		SigningTime: testhelper.GetRSALeafCertificate().Cert.NotBefore,
		Expiry:      testhelper.GetRSALeafCertificate().Cert.NotAfter,
		SigningScheme: signiningSchema,
		Signer: &mockSigner{
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			certs: []*x509.Certificate{
				testhelper.GetRSALeafCertificate().Cert,
				testhelper.GetRSARootCertificate().Cert,
			},
		},
		SigningAgent: invalidSigningAgent,
	}
)

func init() {
	time08_02, _ = time.Parse(timeLayout, "2020-08-02")
	time08_03, _ = time.Parse(timeLayout, "2020-08-03")
}

// Mock an internal envelope that implements signature.Envelope.
type mockEnvelope struct {
	payload    *signature.Payload
	signerInfo *signature.SignerInfo
	content    *signature.EnvelopeContent
	failVerify bool
}

// Sign implements Sign of signature.Envelope.
func (e mockEnvelope) Sign(req *signature.SignRequest) ([]byte, error) {
	switch req.SigningAgent {
	case invalidSigningAgent:
		return nil, errors.New(errMsg)
	case validSigningAgent:
		return validBytes, nil
	}
	return nil, nil
}

// Verify implements Verify of signature.Envelope.
func (e mockEnvelope) Verify() (*signature.EnvelopeContent, error) {
	if e.failVerify {
		return nil, errors.New(errMsg)
	}
	return e.content, nil
}

// SignerInfo implements SignerInfo of signature.Envelope.
func (e mockEnvelope) Content() (*signature.EnvelopeContent, error) {
	if e.content == nil {
		return nil, errors.New(errMsg)
	}
	return e.content, nil
}

// Mock a signer implements signature.Signer.
type mockSigner struct {
	certs   []*x509.Certificate
	keySpec signature.KeySpec
}

// CertificateChain implements CertificateChain of signature.Signer.
func (s *mockSigner) CertificateChain() ([]*x509.Certificate, error) {
	if len(s.certs) == 0 {
		return nil, errors.New(errMsg)
	}
	return s.certs, nil
}

// Sign implements Sign of signature.Signer.
func (s *mockSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	return nil, nil, nil
}

// KeySpec implements KeySpec of signature.Signer.
func (s *mockSigner) KeySpec() (signature.KeySpec, error) {
	var emptyKeySpec signature.KeySpec
	if s.keySpec == emptyKeySpec {
		return s.keySpec, errors.New(errMsg)
	}
	return s.keySpec, nil
}

func TestSign(t *testing.T) {
	tests := []struct {
		name      string
		req       *signature.SignRequest
		env       *Envelope
		expect    []byte
		expectErr bool
	}{
		{
			name: "invalid request",
			req: &signature.SignRequest{
				SigningTime: time08_02,
				Expiry:      time08_02,
			},
			env: &Envelope{
				Raw:      nil,
				Envelope: mockEnvelope{},
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "internal envelope fails to sign",
			req:  signReq1,
			env: &Envelope{
				Raw:      nil,
				Envelope: mockEnvelope{},
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "internal envelope fails to get content",
			req:  validReq,
			env: &Envelope{
				Raw:      nil,
				Envelope: mockEnvelope{},
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "invalid certificate chain",
			req:  validReq,
			env: &Envelope{
				Raw: nil,
				Envelope: mockEnvelope{
					content: &signature.EnvelopeContent{},
				},
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "successfully signed",
			req:  validReq,
			env: &Envelope{
				Raw: validBytes,
				Envelope: &mockEnvelope{
					content: &signature.EnvelopeContent{
						SignerInfo: *validSignerInfo,
					},
				},
			},
			expect:    validBytes,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := tt.env.Sign(tt.req)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(sig, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, sig)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name          string
		env           *Envelope
		expectContent *signature.EnvelopeContent
		expectErr     bool
	}{
		{
			name:          "empty raw",
			env:           &Envelope{},
			expectContent: nil,
			expectErr:     true,
		},
		{
			name: "err returned by internal envelope",
			env: &Envelope{
				Raw: validBytes,
				Envelope: &mockEnvelope{
					failVerify: true,
					payload:    validPayload,
				},
			},
			expectContent: nil,
			expectErr:     true,
		},
		{
			name: "payload validation failed after internal envelope verfication",
			env: &Envelope{
				Raw: validBytes,
				Envelope: &mockEnvelope{
					content: &signature.EnvelopeContent{
						Payload: signature.Payload{
							ContentType: invalidContentType,
						},
					},
				},
			},
			expectContent: nil,
			expectErr:     true,
		},
		{
			name: "signerInfo validation failed after internal envelope verfication",
			env: &Envelope{
				Raw: validBytes,
				Envelope: &mockEnvelope{
					content: &signature.EnvelopeContent{
						Payload:    *validPayload,
						SignerInfo: signature.SignerInfo{},
					},
				},
			},
			expectContent: nil,
			expectErr:     true,
		},
		{
			name: "verify successfully",
			env: &Envelope{
				Raw: validBytes,
				Envelope: &mockEnvelope{
					content: &signature.EnvelopeContent{
						Payload:    *validPayload,
						SignerInfo: *validSignerInfo,
					},
				},
			},
			expectContent: &signature.EnvelopeContent{
				Payload:    *validPayload,
				SignerInfo: *validSignerInfo,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := tt.env.Verify()

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(content, tt.expectContent) {
				t.Errorf("expect content: %+v, got %+v", tt.expectContent, content)
			}
		})
	}
}

func TestContent(t *testing.T) {
	tests := []struct {
		name      string
		env       *Envelope
		expect    *signature.EnvelopeContent
		expectErr bool
	}{
		{
			name:      "empty raw",
			env:       &Envelope{},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "err returned by internal envelope",
			env: &Envelope{
				Raw:      validBytes,
				Envelope: &mockEnvelope{},
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "invalid payload",
			env: &Envelope{
				Raw: validBytes,
				Envelope: &mockEnvelope{
					content: &signature.EnvelopeContent{
						Payload: signature.Payload{},
					},
				},
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "valid payload and invalid signerInfo",
			env: &Envelope{
				Raw: validBytes,
				Envelope: &mockEnvelope{
					content: &signature.EnvelopeContent{
						Payload: *validPayload,
					},
					signerInfo: &signature.SignerInfo{},
				},
			},
			expect:    nil,
			expectErr: true,
		},
		{
			name: "valid payload and valid signerInfo",
			env: &Envelope{
				Raw: validBytes,
				Envelope: &mockEnvelope{
					content: &signature.EnvelopeContent{
						Payload:    *validPayload,
						SignerInfo: *validSignerInfo,
					},
				},
			},
			expect:    validEnvelopeContent,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := tt.env.Content()

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(content, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, content)
			}
		})
	}
}

func TestValidateSignRequest(t *testing.T) {
	tests := []struct {
		name      string
		req       *signature.SignRequest
		expectErr bool
	}{
		{
			name:      "invalid payload",
			req:       &signature.SignRequest{},
			expectErr: true,
		},
		{
			name: "invalid signing time",
			req: &signature.SignRequest{
				Payload: signature.Payload{
					ContentType: validContentType,
					Content:     validBytes,
				},
			},
			expectErr: true,
		},
		{
			name: "signer is nil",
			req: &signature.SignRequest{
				Payload: signature.Payload{
					ContentType: validContentType,
					Content:     validBytes,
				},
				SigningTime: time08_02,
				Expiry:      time08_03,
			},
			expectErr: true,
		},
		{
			name: "keySpec is empty",
			req: &signature.SignRequest{
				Payload: signature.Payload{
					ContentType: validContentType,
					Content:     validBytes,
				},
				SigningTime: time08_02,
				Expiry:      time08_03,
				SigningScheme: signiningSchema,
				Signer: &mockSigner{
					certs: []*x509.Certificate{
						testhelper.GetRSALeafCertificate().Cert,
						testhelper.GetRSARootCertificate().Cert,
					},
					keySpec: signature.KeySpec{},
				},
			},
			expectErr: true,
		},
		{
			name: "invalid signing schema",
			req: &signature.SignRequest{
				Payload: signature.Payload{
					ContentType: validContentType,
					Content:     validBytes,
				},
				SigningTime: time08_02,
				Expiry:      time08_03,
				Signer: &mockSigner{
					keySpec: signature.KeySpec{
						Type: signature.KeyTypeRSA,
						Size: 3072,
					},
					certs: []*x509.Certificate{
						testhelper.GetRSALeafCertificate().Cert,
						testhelper.GetRSARootCertificate().Cert,
					},
				},
			},
			expectErr: true,
		},
		{
			name:      "valid request",
			req:       validReq,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSignRequest(tt.req)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestValidateSignerInfo(t *testing.T) {
	tests := []struct {
		name      string
		info      *signature.SignerInfo
		expectErr bool
	}{
		{
			name:      "empty signature",
			info:      &signature.SignerInfo{},
			expectErr: true,
		},
		{
			name: "missing signature algorithm",
			info: &signature.SignerInfo{
				Signature: validBytes,
			},
			expectErr: true,
		},
		{
			name: "invalid signing time",
			info: &signature.SignerInfo{
				Signature:          validBytes,
				SignatureAlgorithm: signature.AlgorithmPS256,
			},
			expectErr: true,
		},
		{
			name: "invalid signing schema",
			info: &signature.SignerInfo{
				Signature:          validBytes,
				SignatureAlgorithm: signature.AlgorithmPS384,
				SignedAttributes: signature.SignedAttributes{
					SigningTime: testhelper.GetRSALeafCertificate().Cert.NotBefore,
					Expiry:      testhelper.GetECLeafCertificate().Cert.NotAfter,
				},
			},
			expectErr: true,
		},
		{
			name:      "valid signerInfo",
			info:      validSignerInfo,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSignerInfo(tt.info)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestValidateSigningTime(t *testing.T) {
	tests := []struct {
		name        string
		signingTime time.Time
		expireTime  time.Time
		expectErr   bool
	}{
		{
			name:        "zero signing time",
			signingTime: time.Time{},
			expireTime:  time.Now(),
			expectErr:   true,
		},
		{
			name:        "no expire time",
			signingTime: time.Now(),
			expireTime:  time.Time{},
			expectErr:   false,
		},
		{
			name:        "expireTime set but invalid",
			signingTime: time08_03,
			expireTime:  time08_02,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSigningAndExpiryTime(tt.signingTime, tt.expireTime)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestValidatePayload(t *testing.T) {
	tests := []struct {
		name      string
		payload   *signature.Payload
		expectErr bool
	}{
		{
			name: "invalid payload content type",
			payload: &signature.Payload{
				ContentType: invalidContentType,
			},
			expectErr: true,
		},
		{
			name: "payload content is empty",
			payload: &signature.Payload{
				ContentType: validContentType,
				Content:     []byte{},
			},
			expectErr: true,
		},
		{
			name:      "valid payload",
			payload:   validPayload,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePayload(tt.payload)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestValidateCertificateChain(t *testing.T) {
	tests := []struct {
		name      string
		certs     []*x509.Certificate
		signTime  time.Time
		alg       signature.Algorithm
		expectErr bool
	}{
		{
			name:      "empty certs",
			certs:     []*x509.Certificate{},
			signTime:  time.Now(),
			alg:       signature.AlgorithmES256,
			expectErr: true,
		},
		{
			name: "invalid certificates",
			certs: []*x509.Certificate{
				testhelper.GetECLeafCertificate().Cert,
			},
			signTime:  time.Now(),
			alg:       signature.AlgorithmES256,
			expectErr: true,
		},
		{
			name: "unmatched signing algorithm",
			certs: []*x509.Certificate{
				testhelper.GetRSALeafCertificate().Cert,
				testhelper.GetRSARootCertificate().Cert,
			},
			signTime:  testhelper.GetRSALeafCertificate().Cert.NotBefore,
			alg:       signature.AlgorithmPS256,
			expectErr: true,
		},
		{
			name: "valid certificate chain",
			certs: []*x509.Certificate{
				testhelper.GetRSALeafCertificate().Cert,
				testhelper.GetRSARootCertificate().Cert,
			},
			signTime:  testhelper.GetRSALeafCertificate().Cert.NotBefore,
			alg:       signature.AlgorithmPS384,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCertificateChain(tt.certs, tt.signTime, tt.alg)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestGetSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		cert      *x509.Certificate
		expect    signature.Algorithm
		expectErr bool
	}{
		{
			name:      "unsupported cert",
			cert:      testhelper.GetUnsupportedRSACert().Cert,
			expect:    0,
			expectErr: true,
		},
		{
			name:      "valid cert",
			cert:      testhelper.GetRSALeafCertificate().Cert,
			expect:    signature.AlgorithmPS384,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := getSignatureAlgorithm(tt.cert)

			if (err != nil) != tt.expectErr {
				t.Errorf("error = %v, expectErr = %v", err, tt.expectErr)
			}
			if !reflect.DeepEqual(alg, tt.expect) {
				t.Errorf("expect %+v, got %+v", tt.expect, alg)
			}
		})
	}
}
