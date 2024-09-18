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
	"strings"
	"testing"
	"time"

	crlutils "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
	"github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestCertCheckStatus(t *testing.T) {
	t.Run("certificate does not have CRLDistributionPoints", func(t *testing.T) {
		cert := &x509.Certificate{}
		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, CertCheckStatusOptions{})
		if r.ServerResults[0].Error.Error() != "CRL is not supported" {
			t.Fatalf("expected CRL is not supported, got %v", r.ServerResults[0].Error)
		}
	})

	t.Run("fetcher is nil", func(t *testing.T) {
		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com"},
		}
		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, CertCheckStatusOptions{})
		if r.ServerResults[0].Error.Error() != "CRL fetcher is nil" {
			t.Fatalf("expected CRL fetcher is nil, got %v", r.ServerResults[0].Error)
		}
	})

	t.Run("download error", func(t *testing.T) {
		memoryCache := cache.NewMemoryCache()

		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com"},
		}
		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: errorRoundTripperMock{}},
		)
		fetcher.Cache = memoryCache

		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, CertCheckStatusOptions{
			Fetcher: fetcher,
		})

		if r.ServerResults[0].Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CRL validate failed", func(t *testing.T) {
		memoryCache := cache.NewMemoryCache()

		cert := &x509.Certificate{
			CRLDistributionPoints: []string{"http://example.com"},
		}
		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: expiredCRLRoundTripperMock{}},
		)
		fetcher.Cache = memoryCache

		r := CertCheckStatus(context.Background(), cert, &x509.Certificate{}, CertCheckStatusOptions{
			Fetcher: fetcher,
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
		memoryCache := cache.NewMemoryCache()

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

		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: expectedRoundTripperMock{Body: crlBytes}},
		)
		fetcher.Cache = memoryCache
		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			Fetcher: fetcher,
		})
		if r.Result != result.ResultRevoked {
			t.Fatalf("expected revoked, got %s", r.Result)
		}
	})

	t.Run("unknown critical extension", func(t *testing.T) {
		memoryCache := cache.NewMemoryCache()

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

		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: expectedRoundTripperMock{Body: crlBytes}},
		)
		fetcher.Cache = memoryCache
		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			Fetcher: fetcher,
		})
		if r.ServerResults[0].Error == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("Not revoked", func(t *testing.T) {
		memoryCache := cache.NewMemoryCache()

		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(20240720),
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: expectedRoundTripperMock{Body: crlBytes}},
		)
		fetcher.Cache = memoryCache
		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			Fetcher: fetcher,
		})
		if r.Result != result.ResultOK {
			t.Fatalf("expected OK, got %s", r.Result)
		}
	})

	t.Run("CRL with delta CRL is not checked", func(t *testing.T) {
		memoryCache := cache.NewMemoryCache()

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
		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: expectedRoundTripperMock{Body: crlBytes}},
		)
		fetcher.Cache = memoryCache
		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			Fetcher: fetcher,
		})
		if !errors.Is(r.ServerResults[0].Error, ErrDeltaCRLNotSupported) {
			t.Fatal("expected ErrDeltaCRLNotChecked")
		}
	})

	memoryCache := cache.NewMemoryCache()

	// create a stale CRL
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
	bundle := &cache.Bundle{
		BaseCRL: crl,
		Metadata: cache.Metadata{
			BaseCRL: cache.CRLMetadata{
				URL:        "http://example.com",
				NextUpdate: crl.NextUpdate,
			},
			CachedAt: time.Now(),
		},
	}
	chain[0].Cert.CRLDistributionPoints = []string{"http://example.com"}

	t.Run("invalid stale CRL cache, and re-download failed", func(t *testing.T) {
		// save to cache
		if err := memoryCache.Set(context.Background(), "http://example.com", bundle); err != nil {
			t.Fatal(err)
		}

		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: errorRoundTripperMock{}},
		)
		fetcher.Cache = memoryCache
		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			Fetcher: fetcher,
		})
		if !strings.HasPrefix(r.ServerResults[0].Error.Error(), "failed to download CRL from") {
			t.Fatalf("unexpected error, got %v", r.ServerResults[0].Error)
		}
	})

	t.Run("invalid stale CRL cache, re-download and still validate failed", func(t *testing.T) {
		// save to cache
		if err := memoryCache.Set(context.Background(), "http://example.com", bundle); err != nil {
			t.Fatal(err)
		}

		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: expectedRoundTripperMock{Body: crlBytes}},
		)
		fetcher.Cache = memoryCache
		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			Fetcher: fetcher,
		})
		if !strings.HasPrefix(r.ServerResults[0].Error.Error(), "failed to validate CRL from") {
			t.Fatalf("unexpected error, got %v", r.ServerResults[0].Error)
		}
	})

	t.Run("invalid stale CRL cache, re-download and validate seccessfully", func(t *testing.T) {
		// save to cache
		if err := memoryCache.Set(context.Background(), "http://example.com", bundle); err != nil {
			t.Fatal(err)
		}

		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			NextUpdate: time.Now().Add(time.Hour),
			Number:     big.NewInt(20240720),
		}, issuerCert, issuerKey)
		if err != nil {
			t.Fatal(err)
		}

		fetcher := crlutils.NewHTTPFetcher(
			&http.Client{Transport: expectedRoundTripperMock{Body: crlBytes}},
		)
		fetcher.Cache = memoryCache
		r := CertCheckStatus(context.Background(), chain[0].Cert, issuerCert, CertCheckStatusOptions{
			Fetcher: fetcher,
		})
		if r.Result != result.ResultOK {
			t.Fatalf("expected OK, got %s", r.Result)
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
