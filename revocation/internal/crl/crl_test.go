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
	t.Run("certificate is nil", func(t *testing.T) {
		r := CertCheckStatus(context.Background(), nil, nil, CertCheckStatusOptions{})
		if r.CRLResults[0].Error.Error() != "certificate should not be nil" {
			t.Fatalf("unexpected error, got %v", r.CRLResults[0].Error)
		}
	})
	t.Run("certificate does not support CRL", func(t *testing.T) {
		r := CertCheckStatus(context.Background(), &x509.Certificate{}, &x509.Certificate{}, CertCheckStatusOptions{
			HTTPClient: http.DefaultClient,
		})
		if r.CRLResults[0].Error == nil {
			t.Fatal("expected error")
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
		if r.CRLResults[0].Error == nil {
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
		if r.CRLResults[0].Error == nil {
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
					ReasonCode:     int(result.CRLReasonCodeUnspecified),
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
					ReasonCode:     int(result.CRLReasonCodeUnspecified),
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
		if r.CRLResults[0].Error == nil {
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
		if !errors.Is(r.CRLResults[0].Error, ErrDeltaCRLNotSupported) {
			t.Fatal("expected ErrDeltaCRLNotChecked")
		}
	})

	t.Run("nil issuer", func(t *testing.T) {
		r := CertCheckStatus(context.Background(), chain[0].Cert, nil, CertCheckStatusOptions{})
		if r.CRLResults[0].Error.Error() != "issuer certificate should not be nil" {
			t.Fatalf("unexpected error, got %v", r.CRLResults[0].Error)
		}
	})

	t.Run("http client is nil", func(t *testing.T) {
		// failed to download CRL with a mocked HTTP client
		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{})
		if r.Result != result.ResultUnknown {
			t.Fatalf("expected Unknown, got %s", r.Result)
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
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
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
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
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
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
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
					ReasonCode:     int(result.CRLReasonCodeCertificateHold),
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
		r, err := checkRevocation(cert, baseCRL, signingTime, "")
		if err != nil {
			t.Fatal(err)
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
		r, err := checkRevocation(cert, baseCRL, signingTime, "")
		if err != nil {
			t.Fatal(err)
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
		r, err := checkRevocation(cert, baseCRL, signingTime, "")
		if err != nil {
			t.Fatal(err)
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
		r, err := checkRevocation(cert, baseCRL, signingTime, "")
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
