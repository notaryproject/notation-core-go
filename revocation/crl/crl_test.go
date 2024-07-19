package crl

import (
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
	"github.com/notaryproject/notation-core-go/revocation/result"
)

func TestValidCert(t *testing.T) {
	tempDir := t.TempDir()

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
	cache, err := cache.NewFileSystemCache(tempDir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		CertChain:  certChain,
		HTTPClient: http.DefaultClient,
		Cache:      cache,
	}

	t.Run("validate without cache", func(t *testing.T) {
		r := CertCheckStatus(intermediateCert, rootCert, opts)
		if r.Error != nil {
			t.Fatal(err)
		}
		if r.Result != result.ResultOK {
			t.Fatal("unexpected result")
		}
	})

	t.Run("validate with cache", func(t *testing.T) {
		r := CertCheckStatus(intermediateCert, rootCert, opts)
		if r.Error != nil {
			t.Fatal(err)
		}
		if r.Result != result.ResultOK {
			t.Fatal("unexpected result")
		}
	})
}

func TestRevoked(t *testing.T) {
	tempDir := t.TempDir()

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
	cache, err := cache.NewFileSystemCache(tempDir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		CertChain:  certChain,
		HTTPClient: http.DefaultClient,
		Cache:      cache,
	}

	r := CertCheckStatus(intermediateCert, rootCert, opts)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if r.Result != result.ResultRevoked {
		t.Fatal("unexpected result")
	}
}

func TestMSCert(t *testing.T) {
	tempDir := t.TempDir()

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
	cache, err := cache.NewFileSystemCache(tempDir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{
		CertChain:  certChain,
		HTTPClient: http.DefaultClient,
		Cache:      cache,
	}

	r := CertCheckStatus(intermediateCert, rootCert, opts)
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
