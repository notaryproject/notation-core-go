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
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestCertCheckStatus(t *testing.T) {
	t.Run("certtificate does not have CRLDistributionPoints", func(t *testing.T) {
		cert := &x509.Certificate{}
		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, CertCheckStatusOptions{})
		if r.Result != result.ResultNonRevokable {
			t.Fatalf("expected NonRevokable, got %s", r.Result)
		}
	})

	t.Run("download error", func(t *testing.T) {
		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com"},
		}
		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Transport: errorRoundTripperMock{},
			},
		})
		if r.ServerResults[0].Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CRL validate failed", func(t *testing.T) {
		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com"},
		}
		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Transport: expiredCRLRoundTripperMock{},
			},
		})
		if r.ServerResults[0].Error == nil {
			t.Fatal("expected error")
		}
	})

	// prepare a certificate chain
	chain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	issuerCert := chain[1].Cert
	issuerKey := chain[1].PrivateKey

	t.Run("revoked", func(t *testing.T) {
		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(20240720),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   chain[0].Cert.SerialNumber,
					RevocationTime: time.Now().Add(-time.Hour),
				},
			},
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Transport: expectedRoundTripperMock{Body: crlBytes},
			},
		})
		if r.Result != result.ResultRevoked {
			t.Fatalf("expected revoked, got %s", r.Result)
		}
	})

	t.Run("unknown critical extension", func(t *testing.T) {
		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(20240720),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   chain[0].Cert.SerialNumber,
					RevocationTime: time.Now().Add(-time.Hour),
					ExtraExtensions: []pkix.Extension{
						{
							Id:       []int{1, 2, 3},
							Critical: true,
						},
					},
				},
			},
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Transport: expectedRoundTripperMock{Body: crlBytes},
			},
		})
		if r.ServerResults[0].Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("Not revoked", func(t *testing.T) {
		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(20240720),
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Transport: expectedRoundTripperMock{Body: crlBytes},
			},
		})
		if r.Result != result.ResultOK {
			t.Fatalf("expected OK, got %s", r.Result)
		}
	})

	t.Run("CRL with delta CRL is not checked", func(t *testing.T) {
		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(20240720),
			ExtraExtensions: []pkix.Extension{
				{
					Id:       oidFreshestCRL,
					Critical: false,
				},
			},
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			HTTPClient: &http.Client{
				Transport: expectedRoundTripperMock{Body: crlBytes},
			},
		})
		if !errors.Is(r.ServerResults[0].Error, ErrDeltaCRLNotSupported) {
			t.Fatal("expected ErrDeltaCRLNotChecked")
		}
	})
}

func TestValidate(t *testing.T) {
	t.Run("expired CRL", func(t *testing.T) {
		chain := testhelper.GetRevokableRSAChainWithRevocations(1, false, true)
		issuerCert := chain[0].Cert
		issuerKey := chain[0].PrivateKey

		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(-time.Hour),
			Number:     big.NewInt(20240720),
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatal(err)
		}

		if err := validate(crl, issuerCert); err == nil {
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
		chain := testhelper.GetRevokableRSAChainWithRevocations(1, false, true)
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

	t.Run("issuing distribution point extension exists", func(t *testing.T) {
		chain := testhelper.GetRevokableRSAChainWithRevocations(1, false, true)
		issuerCert := chain[0].Cert
		issuerKey := chain[0].PrivateKey

		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(20240720),
			ExtraExtensions: []pkix.Extension{
				{
					Id:       oidIssuingDistributionPoint,
					Critical: true,
				},
			},
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatal(err)
		}

		if err := validate(crl, issuerCert); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCheckRevocation(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	signingTime := time.Now()

	t.Run("certificate is nil", func(t *testing.T) {
		_, err := checkRevocation(nil, &x509.RevocationList{}, signingTime, "")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CRL is nil", func(t *testing.T) {
		_, err := checkRevocation(cert, nil, signingTime, "")
		if err == nil {
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
		r, err := checkRevocation(cert, baseCRL, signingTime, "")
		if err != nil {
			t.Fatal(err)
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
					RevocationTime: time.Now().Add(-time.Hour),
				},
			},
		}
		r, err := checkRevocation(cert, baseCRL, signingTime, "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Result != result.ResultRevoked {
			t.Fatalf("expected revoked, got %s", r.Result)
		}
	})

	t.Run("revoked but signing time is before invalidityDate", func(t *testing.T) {
		invalidityDate := time.Now().Add(time.Hour)
		invalidityDateBytes, err := marshalGeneralizedTimeToBytes(invalidityDate)
		if err != nil {
			t.Fatal(err)
		}

		extensions := []pkix.Extension{
			{
				Id:       oidInvalidityDate,
				Critical: false,
				Value:    invalidityDateBytes,
			},
		}

		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					RevocationTime: time.Now().Add(time.Hour),
					Extensions:     extensions,
				},
			},
		}
		r, err := checkRevocation(cert, baseCRL, signingTime, "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Result != result.ResultOK {
			t.Fatalf("unexpected result, got %s", r.Result)
		}
	})

	t.Run("revoked; signing time is after invalidityDate", func(t *testing.T) {
		invalidityDate := time.Now().Add(-time.Hour)
		invalidityDateBytes, err := marshalGeneralizedTimeToBytes(invalidityDate)
		if err != nil {
			t.Fatal(err)
		}

		extensions := []pkix.Extension{
			{
				Id:       oidInvalidityDate,
				Critical: false,
				Value:    invalidityDateBytes,
			},
		}

		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					RevocationTime: time.Now().Add(-time.Hour),
					Extensions:     extensions,
				},
			},
		}
		r, err := checkRevocation(cert, baseCRL, signingTime, "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Result != result.ResultRevoked {
			t.Fatalf("expected revoked, got %s", r.Result)
		}
	})

	t.Run("revoked and signing time is zero", func(t *testing.T) {
		baseCRL := &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(1),
					RevocationTime: time.Time{},
				},
			},
		}
		r, err := checkRevocation(cert, baseCRL, time.Time{}, "")
		if err != nil {
			t.Fatal(err)
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
					Extensions: []pkix.Extension{
						{
							Id:       []int{1, 2, 3},
							Critical: true,
						},
					},
				},
			},
		}
		_, err := checkRevocation(cert, baseCRL, signingTime, "")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestParseEntryExtension(t *testing.T) {
	t.Run("unsupported critical extension", func(t *testing.T) {
		entry := x509.RevocationListEntry{
			Extensions: []pkix.Extension{
				{
					Id:       []int{1, 2, 3},
					Critical: true,
				},
			},
		}
		if _, err := parseEntryExtensions(entry); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("valid extension", func(t *testing.T) {
		entry := x509.RevocationListEntry{
			Extensions: []pkix.Extension{
				{
					Id:       []int{1, 2, 3},
					Critical: false,
				},
			},
		}
		if _, err := parseEntryExtensions(entry); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("parse invalidityDate", func(t *testing.T) {

		// create a time and marshal it to be generalizedTime
		invalidityDate := time.Now()
		invalidityDateBytes, err := marshalGeneralizedTimeToBytes(invalidityDate)
		if err != nil {
			t.Fatal(err)
		}

		entry := x509.RevocationListEntry{
			Extensions: []pkix.Extension{
				{
					Id:       oidInvalidityDate,
					Critical: false,
					Value:    invalidityDateBytes,
				},
			},
		}
		extensions, err := parseEntryExtensions(entry)
		if err != nil {
			t.Fatal(err)
		}

		if extensions.invalidityDate.IsZero() {
			t.Fatal("expected invalidityDate")
		}
	})

	t.Run("parse invalidityDate with error", func(t *testing.T) {
		// invalid invalidityDate extension
		entry := x509.RevocationListEntry{
			Extensions: []pkix.Extension{
				{
					Id:       oidInvalidityDate,
					Critical: false,
					Value:    []byte{0x00, 0x01, 0x02, 0x03},
				},
			},
		}
		_, err := parseEntryExtensions(entry)
		if err == nil {
			t.Fatal("expected error")
		}

		// invalidityDate extension with extra bytes
		invalidityDate := time.Now()
		invalidityDateBytes, err := marshalGeneralizedTimeToBytes(invalidityDate)
		if err != nil {
			t.Fatal(err)
		}
		invalidityDateBytes = append(invalidityDateBytes, 0x00)

		entry = x509.RevocationListEntry{
			Extensions: []pkix.Extension{
				{
					Id:       oidInvalidityDate,
					Critical: false,
					Value:    invalidityDateBytes,
				},
			},
		}
		_, err = parseEntryExtensions(entry)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// marshalGeneralizedTimeToBytes converts a time.Time to ASN.1 GeneralizedTime bytes.
func marshalGeneralizedTimeToBytes(t time.Time) ([]byte, error) {
	// ASN.1 GeneralizedTime requires the time to be in UTC
	t = t.UTC()
	// Use asn1.Marshal to directly get the ASN.1 GeneralizedTime bytes
	return asn1.Marshal(t)
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

	t.Run("exceed the size limit", func(t *testing.T) {
		_, err := download(context.Background(), "http://example.com", &http.Client{
			Transport: expectedRoundTripperMock{Body: make([]byte, maxCRLSize+1)},
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestSupported(t *testing.T) {
	t.Run("supported", func(t *testing.T) {
		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com"},
		}
		if !Supported(cert) {
			t.Fatal("expected supported")
		}
	})

	t.Run("unsupported", func(t *testing.T) {
		cert := &x509.Certificate{}
		if Supported(cert) {
			t.Fatal("expected unsupported")
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
		Request:    req,
		StatusCode: http.StatusInternalServerError,
	}, nil
}

type readFailedRoundTripperMock struct{}

func (rt readFailedRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       errorReaderMock{},
		Request: &http.Request{
			Method: http.MethodGet,
			URL:    req.URL,
		},
	}, nil
}

type expiredCRLRoundTripperMock struct{}

func (rt expiredCRLRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	chain := testhelper.GetRevokableRSAChainWithRevocations(1, false, true)
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

type expectedRoundTripperMock struct {
	Body []byte
}

func (rt expectedRoundTripperMock) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Request:    req,
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBuffer(rt.Body)),
	}, nil
}
