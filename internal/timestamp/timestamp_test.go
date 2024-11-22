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

package timestamp

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/notaryproject/notation-core-go/revocation"
	"github.com/notaryproject/notation-core-go/revocation/result"
	"github.com/notaryproject/notation-core-go/signature"
	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/tspclient-go"
	"github.com/notaryproject/tspclient-go/pki"
)

const rfc3161TSAurl = "http://rfc3161timestamp.globalsign.com/advanced"

func TestTimestamp(t *testing.T) {
	rootCerts, err := nx509.ReadCertificateFile("testdata/tsaRootCert.crt")
	if err != nil || len(rootCerts) == 0 {
		t.Fatal("failed to read root CA certificate:", err)
	}
	rootCert := rootCerts[0]
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCert)

	// --------------- Success case ----------------------------------
	t.Run("Timestamping success", func(t *testing.T) {
		timestamper, err := tspclient.NewHTTPTimestamper(nil, rfc3161TSAurl)
		if err != nil {
			t.Fatal(err)
		}
		req := &signature.SignRequest{
			Timestamper: timestamper,
			TSARootCAs:  rootCAs,
		}
		opts := tspclient.RequestOptions{
			Content:       []byte("notation"),
			HashAlgorithm: crypto.SHA256,
		}
		_, err = Timestamp(req, opts)
		if err != nil {
			t.Fatal(err)
		}
	})

	// ------------- Failure cases ------------------------
	t.Run("Timestamping SHA-1", func(t *testing.T) {
		timestamper, err := tspclient.NewHTTPTimestamper(nil, rfc3161TSAurl)
		if err != nil {
			t.Fatal(err)
		}
		req := &signature.SignRequest{
			Timestamper: timestamper,
			TSARootCAs:  rootCAs,
		}
		opts := tspclient.RequestOptions{
			Content:       []byte("notation"),
			HashAlgorithm: crypto.SHA1,
		}
		expectedErr := "malformed timestamping request: unsupported hashing algorithm: SHA-1"
		_, err = Timestamp(req, opts)
		assertErrorEqual(expectedErr, err, t)
	})

	t.Run("Timestamping failed", func(t *testing.T) {
		req := &signature.SignRequest{
			Timestamper: dummyTimestamper{},
			TSARootCAs:  rootCAs,
		}
		opts := tspclient.RequestOptions{
			Content:       []byte("notation"),
			HashAlgorithm: crypto.SHA256,
		}
		expectedErr := "failed to timestamp"
		_, err = Timestamp(req, opts)
		if err == nil || !strings.Contains(err.Error(), expectedErr) {
			t.Fatalf("expected error message to contain %s, but got %v", expectedErr, err)
		}
	})

	t.Run("Timestamping rejected", func(t *testing.T) {
		req := &signature.SignRequest{
			Timestamper: dummyTimestamper{
				respWithRejectedStatus: true,
			},
			TSARootCAs: rootCAs,
		}
		opts := tspclient.RequestOptions{
			Content:       []byte("notation"),
			HashAlgorithm: crypto.SHA256,
		}
		expectedErr := "invalid timestamping response: invalid response with status code 2: rejected"
		_, err = Timestamp(req, opts)
		assertErrorEqual(expectedErr, err, t)
	})

	t.Run("Timestamping cms verification failure", func(t *testing.T) {
		opts := tspclient.RequestOptions{
			Content:       []byte("notation"),
			HashAlgorithm: crypto.SHA256,
		}
		req := &signature.SignRequest{
			Timestamper: dummyTimestamper{
				invalidSignature: true,
			},
			TSARootCAs: rootCAs,
		}
		expectedErr := "failed to verify signed token: cms verification failure: crypto/rsa: verification error"
		_, err = Timestamp(req, opts)
		assertErrorEqual(expectedErr, err, t)
	})

	t.Run("Timestamping revocation failed", func(t *testing.T) {
		timestamper, err := tspclient.NewHTTPTimestamper(nil, rfc3161TSAurl)
		if err != nil {
			t.Fatal(err)
		}
		req := &signature.SignRequest{
			Timestamper: timestamper,
			TSARootCAs:  rootCAs,
			TSARevocationValidator: &dummyTSARevocationValidator{
				failOnValidate: true,
			},
		}
		opts := tspclient.RequestOptions{
			Content:       []byte("notation"),
			HashAlgorithm: crypto.SHA256,
		}
		expectedErr := "after timestamping: failed to check timestamping certificate chain revocation with error: failed in ValidateContext"
		_, err = Timestamp(req, opts)
		assertErrorEqual(expectedErr, err, t)
	})

	t.Run("Timestamping certificate revoked", func(t *testing.T) {
		timestamper, err := tspclient.NewHTTPTimestamper(nil, rfc3161TSAurl)
		if err != nil {
			t.Fatal(err)
		}
		req := &signature.SignRequest{
			Timestamper: timestamper,
			TSARootCAs:  rootCAs,
			TSARevocationValidator: &dummyTSARevocationValidator{
				revoked: true,
			},
		}
		opts := tspclient.RequestOptions{
			Content:       []byte("notation"),
			HashAlgorithm: crypto.SHA256,
		}
		expectedErr := `after timestamping: timestamping certificate with subject "CN=Globalsign TSA for Advanced - G4 - 202311,O=GlobalSign nv-sa,C=BE" is revoked`
		_, err = Timestamp(req, opts)
		assertErrorEqual(expectedErr, err, t)
	})

}

func TestRevocationFinalResult(t *testing.T) {
	certResult := []*result.CertRevocationResult{
		{
			// update leaf cert result in each sub-test
		},
		{
			Result: result.ResultNonRevokable,
			ServerResults: []*result.ServerResult{
				{
					Result: result.ResultNonRevokable,
				},
			},
		},
	}
	certChain := []*x509.Certificate{
		{
			Subject: pkix.Name{
				CommonName: "leafCert",
			},
		},
		{
			Subject: pkix.Name{
				CommonName: "rootCert",
			},
		},
	}
	t.Run("OCSP error without fallback", func(t *testing.T) {
		certResult[0] = &result.CertRevocationResult{
			Result: result.ResultUnknown,
			ServerResults: []*result.ServerResult{
				{
					Result:           result.ResultUnknown,
					Error:            errors.New("ocsp error"),
					RevocationMethod: result.RevocationMethodOCSP,
				},
			},
		}
		err := revocationFinalResult(certResult, certChain)
		assertErrorEqual(`timestamping certificate with subject "CN=leafCert" revocation status is unknown`, err, t)
	})

	t.Run("OCSP error with fallback", func(t *testing.T) {
		certResult[0] = &result.CertRevocationResult{
			Result: result.ResultOK,
			ServerResults: []*result.ServerResult{
				{
					Result:           result.ResultUnknown,
					Error:            errors.New("ocsp error"),
					RevocationMethod: result.RevocationMethodOCSP,
				},
				{
					Result:           result.ResultOK,
					RevocationMethod: result.RevocationMethodCRL,
				},
			},
			RevocationMethod: result.RevocationMethodOCSPFallbackCRL,
		}
		if err := revocationFinalResult(certResult, certChain); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("OCSP error with fallback and CRL error", func(t *testing.T) {
		certResult[0] = &result.CertRevocationResult{
			Result: result.ResultUnknown,
			ServerResults: []*result.ServerResult{
				{
					Result:           result.ResultUnknown,
					Error:            errors.New("ocsp error"),
					RevocationMethod: result.RevocationMethodOCSP,
				},
				{
					Result:           result.ResultUnknown,
					Error:            errors.New("crl error"),
					RevocationMethod: result.RevocationMethodCRL,
				},
			},
			RevocationMethod: result.RevocationMethodOCSPFallbackCRL,
		}
		err := revocationFinalResult(certResult, certChain)
		assertErrorEqual(`timestamping certificate with subject "CN=leafCert" revocation status is unknown`, err, t)
	})

	t.Run("revoked", func(t *testing.T) {
		certResult[0] = &result.CertRevocationResult{
			Result: result.ResultRevoked,
			ServerResults: []*result.ServerResult{
				{
					Result:           result.ResultRevoked,
					Error:            errors.New("revoked"),
					RevocationMethod: result.RevocationMethodCRL,
				},
			},
		}
		err := revocationFinalResult(certResult, certChain)
		assertErrorEqual(`timestamping certificate with subject "CN=leafCert" is revoked`, err, t)
	})

	t.Run("revocation method unknown error(should never reach here)", func(t *testing.T) {
		certResult[0] = &result.CertRevocationResult{
			Result: result.ResultUnknown,
			ServerResults: []*result.ServerResult{
				{
					Result:           result.ResultUnknown,
					Error:            errors.New("unknown error"),
					RevocationMethod: result.RevocationMethodUnknown,
				},
			},
		}
		err := revocationFinalResult(certResult, certChain)
		assertErrorEqual(`timestamping certificate with subject "CN=leafCert" revocation status is unknown`, err, t)
	})
}

func assertErrorEqual(expected string, err error, t *testing.T) {
	if err == nil || expected != err.Error() {
		t.Fatalf("Expected error \"%v\" but was \"%v\"", expected, err)
	}
}

type dummyTimestamper struct {
	respWithRejectedStatus bool
	invalidSignature       bool
}

func (d dummyTimestamper) Timestamp(context.Context, *tspclient.Request) (*tspclient.Response, error) {
	if d.respWithRejectedStatus {
		return &tspclient.Response{
			Status: pki.StatusInfo{
				Status: pki.StatusRejection,
			},
		}, nil
	}
	if d.invalidSignature {
		token, err := os.ReadFile("testdata/TimeStampTokenWithInvalidSignature.p7s")
		if err != nil {
			return nil, err
		}
		return &tspclient.Response{
			Status: pki.StatusInfo{
				Status: pki.StatusGranted,
			},
			TimestampToken: asn1.RawValue{
				FullBytes: token,
			},
		}, nil
	}
	return nil, errors.New("failed to timestamp")
}

type dummyTSARevocationValidator struct {
	failOnValidate bool
	revoked        bool
}

func (v *dummyTSARevocationValidator) ValidateContext(ctx context.Context, validateContextOpts revocation.ValidateContextOptions) ([]*result.CertRevocationResult, error) {
	if v.failOnValidate {
		return nil, errors.New("failed in ValidateContext")
	}
	if v.revoked {
		var certResult []*result.CertRevocationResult
		certResult = append(certResult, &result.CertRevocationResult{
			Result: result.ResultRevoked,
			ServerResults: []*result.ServerResult{
				{
					Result:           result.ResultRevoked,
					Error:            errors.New("revoked"),
					RevocationMethod: result.RevocationMethodCRL,
				},
			},
		})
		return certResult, nil
	}
	return nil, nil
}
