package crl

import (
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/notaryproject/notation-core-go/revocation/result"
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

	certChain := []*x509.Certificate{intermediateCert, rootCert}
	opts := Options{
		CertChain:  certChain,
		HTTPClient: http.DefaultClient,
		Cache:      NewFileSystemCache(filepath.Join("testdata", "cache")),
	}

	r := CertCheckStatus(intermediateCert, rootCert, opts)
	if r.Err != nil {
		t.Fatal(err)
	}
	if r.Result != result.ResultOK {
		t.Fatal("unexpected result")
	}
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

	certChain := []*x509.Certificate{intermediateCert, rootCert}
	opts := Options{
		CertChain:  certChain,
		HTTPClient: http.DefaultClient,
		Cache:      NewFileSystemCache(filepath.Join("testdata", "cache")),
	}

	r := CertCheckStatus(intermediateCert, rootCert, opts)
	if r.Err != nil {
		t.Fatal(err)
	}
	if r.Result != result.ResultRevoked {
		t.Fatal("unexpected result")
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

	certChain := []*x509.Certificate{intermediateCert, rootCert}
	opts := Options{
		CertChain:  certChain,
		HTTPClient: http.DefaultClient,
		Cache:      NewFileSystemCache(filepath.Join("testdata", "cache")),
	}

	r := CertCheckStatus(intermediateCert, rootCert, opts)
	if r.Err != nil {
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
