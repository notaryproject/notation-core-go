package x509

import (
	"crypto/x509"
	"testing"
)

func TestLoadPemFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/pem.crt")
	verifyNoError(t, err)
	verifyNumCerts(t, certs, 1)
}

func TestLoadMultiPemFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/multi-pem.crt")
	verifyNoError(t, err)
	verifyNumCerts(t, certs, 2)
}

func TestLoadDerFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/der.der")
	verifyNoError(t, err)
	verifyNumCerts(t, certs, 1)
}

func TestLoadMultiDerFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/multi-der.der")
	verifyNoError(t, err)
	verifyNumCerts(t, certs, 2)
}

func TestLoadInvalidFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/invalid")
	if err == nil {
		t.Fatalf("invalid file should throw an error")
	}
	verifyNumCerts(t, certs, 0)
}

func verifyNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Error : %q", err)
	}
}

func verifyNumCerts(t *testing.T, certs []*x509.Certificate, num int) {
	if len(certs) != num {
		t.Fatalf("test case should return only %d certificate/s", num)
	}
}
