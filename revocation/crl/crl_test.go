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

package crl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestValidCert(t *testing.T) {
	// read intermediate cert file
	intermediateCert, err := loadCertFile(filepath.Join("testdata", "valid", "valid.cer"))
	if err != nil {
		t.Fatal(err)
	}

	rootCert, err := loadCertFile(filepath.Join("testdata", "valid", "root.cer"))
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		HTTPClient: http.DefaultClient,
	}

	t.Run("validate without cache", func(t *testing.T) {
		r := CertCheckStatus(context.Background(), intermediateCert, rootCert, opts)
		if r.Error != nil {
			t.Fatal(err)
		}
		if r.Result != result.ResultOK {
			t.Fatal("unexpected result")
		}
	})

	t.Run("validate with cache", func(t *testing.T) {
		r := CertCheckStatus(context.Background(), intermediateCert, rootCert, opts)
		if r.Error != nil {
			t.Fatal(err)
		}
		if r.Result != result.ResultOK {
			t.Fatal("unexpected result")
		}
	})
}

func TestRevoked(t *testing.T) {
	// read intermediate cert file
	intermediateCert, err := loadCertFile(filepath.Join("testdata", "revoked", "revoked.cer"))
	if err != nil {
		t.Fatal(err)
	}

	rootCert, err := loadCertFile(filepath.Join("testdata", "revoked", "root.cer"))
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		HTTPClient: http.DefaultClient,
	}

	r := CertCheckStatus(context.Background(), intermediateCert, rootCert, opts)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if r.Result != result.ResultRevoked {
		t.Fatalf("unexpected result, got %s", r.Result)
	}
}

func TestMSCert(t *testing.T) {

	// read intermediate cert file
	intermediateCert, err := loadCertFile(filepath.Join("testdata", "ms", "msleaf.cer"))
	if err != nil {
		t.Fatal(err)
	}

	rootCert, err := loadCertFile(filepath.Join("testdata", "ms", "msintermediate.cer"))
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		HTTPClient: http.DefaultClient,
	}

	r := CertCheckStatus(context.Background(), intermediateCert, rootCert, opts)
	if r.Error != nil {
		t.Fatal(err)
	}
	if r.Result != result.ResultOK {
		t.Fatal("unexpected result")
	}
}

func loadCertFile(certPath string) (*x509.Certificate, error) {
	intermediateCert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(intermediateCert)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func TestCertCheckStatus(t *testing.T) {
	t.Run("http client is nil", func(t *testing.T) {
		r := CertCheckStatus(context.Background(), &x509.Certificate{}, &x509.Certificate{}, Options{})
		if r.Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("certificate does not support CRL", func(t *testing.T) {
		r := CertCheckStatus(context.Background(), &x509.Certificate{}, &x509.Certificate{}, Options{
			HTTPClient: http.DefaultClient,
		})
		if r.Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("download error", func(t *testing.T) {
		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com"},
		}
		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, Options{
			HTTPClient: &http.Client{
				Transport: errorRoundTripperMock{},
			},
		})
		if r.Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CRL validate failed", func(t *testing.T) {
		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com"},
		}
		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, Options{
			HTTPClient: &http.Client{
				Transport: expiredCRLRoundTripperMock{},
			},
		})
		if r.Error == nil {
			t.Fatal("expected error")
		}
	})
}

func TestValidate(t *testing.T) {
	t.Run("expired CRL", func(t *testing.T) {
		crl := &x509.RevocationList{
			NextUpdate: time.Now().Add(-time.Hour),
		}

		if err := validate(crl, &x509.Certificate{}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("check signature failed", func(t *testing.T) {
		crl := &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
		}

		if err := validate(crl, &x509.Certificate{}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("unsupported CRL critical extensions", func(t *testing.T) {
		chain := testhelper.GetRevokableRSAChain(1, false, true)
		issuerCert := chain[0].Cert
		issuerKey := chain[0].PrivateKey

		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(20240720),
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatal(err)
		}

		// add unsupported critical extension
		crl.Extensions = []pkix.Extension{
			{
				Id:       []int{1, 2, 3},
				Critical: true,
			},
		}

		if err := validate(crl, issuerCert); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestCheckRevocation(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	signingTime := time.Now()

	t.Run("certificate is nil", func(t *testing.T) {
		r := checkRevocation(nil, &x509.RevocationList{}, signingTime)
		if r.Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CRL is nil", func(t *testing.T) {
		r := checkRevocation(cert, nil, signingTime)
		if r.Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("not revoked", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber: big.NewInt(2),
				},
			},
		}
		r := checkRevocation(cert, baseCRL, signingTime)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if r.Result != result.ResultOK {
			t.Fatalf("unexpected result, got %s", r.Result)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
					RevocationTime: time.Now().Add(-time.Hour),
				},
			},
		}
		r := checkRevocation(cert, baseCRL, signingTime)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if r.Result != result.ResultRevoked {
			t.Fatalf("expected revoked, got %s", r.Result)
		}
	})

	t.Run("revoked but signing time is before revocation time", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
					RevocationTime: time.Now().Add(time.Hour),
				},
			},
		}
		r := checkRevocation(cert, baseCRL, signingTime)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if r.Result != result.ResultOK {
			t.Fatalf("unexpected result, got %s", r.Result)
		}
	})

	t.Run("revoked and signing time is zero", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
					RevocationTime: time.Time{},
				},
			},
		}
		r := checkRevocation(cert, baseCRL, time.Time{})
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if r.Result != result.ResultRevoked {
			t.Fatalf("expected revoked, got %s", r.Result)
		}
	})

	t.Run("revoked but not permanently", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
					RevocationTime: time.Now().Add(-time.Hour),
				},
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeRemoveFromCRL),
					RevocationTime: time.Now().Add(-time.Minute * 10),
				},
			},
		}
		r := checkRevocation(cert, baseCRL, signingTime)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if r.Result != result.ResultOK {
			t.Fatalf("unexpected result, got %s", r.Result)
		}
	})

	t.Run("revoked but not permanently with disordered entry list", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeRemoveFromCRL),
					RevocationTime: time.Now().Add(-time.Minute * 10),
				},
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
					RevocationTime: time.Now().Add(-time.Hour),
				},
			},
		}
		r := checkRevocation(cert, baseCRL, signingTime)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if r.Result != result.ResultOK {
			t.Fatalf("unexpected result, got %s", r.Result)
		}
	})

	t.Run("RemoveFromCRL before CertificateHold", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeRemoveFromCRL),
					RevocationTime: time.Now().Add(-time.Hour),
				},
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
					RevocationTime: time.Now().Add(-time.Minute * 10),
				},
			},
		}
		r := checkRevocation(cert, baseCRL, signingTime)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if r.Result != result.ResultRevoked {
			t.Fatalf("expected revoked, got %s", r.Result)
		}
	})

	t.Run("multiple CertificateHold with RemoveFromCRL and disordered entry list", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
					RevocationTime: time.Now().Add(-time.Minute * 20),
				},
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeRemoveFromCRL),
					RevocationTime: time.Now().Add(-time.Hour),
				},
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
					RevocationTime: time.Now().Add(-time.Minute * 50),
				},
				{
					SerialNumber:   big.NewInt(1),
					ReasonCode:     int(result.CRLReasonCodeRemoveFromCRL),
					RevocationTime: time.Now().Add(-time.Minute * 40),
				},
			},
		}
		r := checkRevocation(cert, baseCRL, signingTime)
		if r.Error != nil {
			t.Fatal(r.Error)
		}
		if r.Result != result.ResultRevoked {
			t.Fatalf("expected revoked, got %s", r.Result)
		}
	})

	t.Run("revocation entry validation error", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber: big.NewInt(1),
					ExtraExtensions: []pkix.Extension{
						{
							Id:       []int{1, 2, 3},
							Critical: true,
						},
					},
				},
			},
		}
		r := checkRevocation(cert, baseCRL, signingTime)
		if r.Error == nil {
			t.Fatal("expected error")
		}
	})
}

func TestValidateRevocationEntry(t *testing.T) {
	t.Run("invalid extension", func(t *testing.T) {
		entry := x509.RevocationListEntry{
			ExtraExtensions: []pkix.Extension{
				{
					Id:       []int{1, 2, 3},
					Critical: true,
				},
			},
		}
		if err := validateRevocationEntry(entry); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("valid extension", func(t *testing.T) {
		entry := x509.RevocationListEntry{
			ExtraExtensions: []pkix.Extension{
				{
					Id:       []int{1, 2, 3},
					Critical: false,
				},
			},
		}
		if err := validateRevocationEntry(entry); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDownload(t *testing.T) {
	t.Run("parse url error", func(t *testing.T) {
		_, err := download(context.Background(), ":", http.DefaultClient)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("https download", func(t *testing.T) {
		_, err := download(context.Background(), "https://example.com", http.DefaultClient)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("http.NewRequestWithContext error", func(t *testing.T) {
		var ctx context.Context = nil
		_, err := download(ctx, "http://example.com", &http.Client{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("client.Do error", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: errorRoundTripperMock{},
		})

		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("status code is not 2xx", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: serverErrorRoundTripperMock{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("readAll error", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: readFailedRoundTripperMock{},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

type errorRoundTripperMock struct{}

func (rt errorRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("error")
}

type serverErrorRoundTripperMock struct{}

func (rt serverErrorRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusInternalServerError,
	}, nil
}

type readFailedRoundTripperMock struct{}

func (rt readFailedRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       errorReaderMock{},
	}, nil
}

type expiredCRLRoundTripperMock struct{}

func (rt expiredCRLRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	chain := testhelper.GetRevokableRSAChain(1, false, true)
	issuerCert := chain[0].Cert
	issuerKey := chain[0].PrivateKey

	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		NextUpdate: time.Now().Add(-time.Hour),
		Number:     big.NewInt(20240720),
	}, issuerCert, issuerKey)
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(crlBytes)),
	}, nil
}

type errorReaderMock struct{}

func (r errorReaderMock) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("error")
}

func (r errorReaderMock) Close() error {
	return nil
}
