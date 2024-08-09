package cache

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/testhelper"
)

func TestNewBundle(t *testing.T) {
	baseCRL := &x509.RevocationList{}
	url := "https://example.com/base.crl"
	bundle, err := NewBundle(baseCRL, url)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if bundle.BaseCRL != baseCRL {
		t.Errorf("expected BaseCRL to be %v, got %v", baseCRL, bundle.BaseCRL)
	}

	if bundle.Metadata.BaseCRL.URL != url {
		t.Errorf("expected URL to be %s, got %s", url, bundle.Metadata.BaseCRL.URL)
	}

	if bundle.Metadata.CreateAt.IsZero() {
		t.Errorf("expected CreateAt to be set, got zero value")
	}
}

func TestBundle(t *testing.T) {
	const exampleURL = "https://example.com/base.crl"
	var buf bytes.Buffer

	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}
	t.Run("SaveAsTarball", func(t *testing.T) {
		// Create a tarball
		baseCRL, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatalf("failed to parse base CRL: %v", err)
		}
		bundle, err := NewBundle(baseCRL, exampleURL)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if err := bundle.SaveAsTarball(&buf); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("ParseBundleFromTarball", func(t *testing.T) {
		// Parse the tarball
		bundle, err := ParseBundleFromTarball(&buf)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !bytes.Equal(crlBytes, bundle.BaseCRL.Raw) {
			t.Errorf("expected BaseCRL to be %v, got %v", crlBytes, bundle.BaseCRL.Raw)
		}

		if bundle.Metadata.BaseCRL.URL != exampleURL {
			t.Errorf("expected URL to be %s, got %s", exampleURL, bundle.Metadata.BaseCRL.URL)
		}

		if bundle.Metadata.CreateAt.IsZero() {
			t.Errorf("expected CreateAt to be set, got zero value")
		}
	})
}

func TestBundleParseFailed(t *testing.T) {
	t.Run("IO read error", func(t *testing.T) {
		_, err := ParseBundleFromTarball(&errorReader{})
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("missing baseCRL content (only has baseCRL header in tarball)", func(t *testing.T) {
		var buf bytes.Buffer
		header := &tar.Header{
			Name:    "base.crl",
			Size:    10,
			Mode:    0644,
			ModTime: time.Now(),
		}
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Close()

		_, err := ParseBundleFromTarball(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("broken baseCRL", func(t *testing.T) {
		var buf bytes.Buffer
		header := &tar.Header{
			Name:    "base.crl",
			Size:    10,
			Mode:    0644,
			ModTime: time.Now(),
		}
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write([]byte("broken crl"))
		tw.Close()

		_, err := ParseBundleFromTarball(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("malformed metadata", func(t *testing.T) {
		var buf bytes.Buffer
		header := &tar.Header{
			Name:    "metadata.json",
			Size:    10,
			Mode:    0644,
			ModTime: time.Now(),
		}
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write([]byte("malformed json"))
		tw.Close()

		_, err := ParseBundleFromTarball(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("unknown file in tarball", func(t *testing.T) {
		var buf bytes.Buffer
		header := &tar.Header{
			Name:    "unknown file",
			Size:    10,
			Mode:    0644,
			ModTime: time.Now(),
		}
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write([]byte("unknown file"))
		tw.Close()

		_, err := ParseBundleFromTarball(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestValidate(t *testing.T) {
	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}

	t.Run("missing BaseCRL", func(t *testing.T) {
		var buf bytes.Buffer
		_, err := ParseBundleFromTarball(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("missing metadata baseCRL URL", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		baseCRLHeader := &tar.Header{
			Name:    "base.crl",
			Size:    int64(len(crlBytes)),
			Mode:    0644,
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(baseCRLHeader); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write(crlBytes)

		metadataContent := []byte(`{"base.crl": {}}`)
		metadataHeader := &tar.Header{
			Name:    "metadata.json",
			Size:    int64(len(metadataContent)),
			Mode:    0644,
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(metadataHeader); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write(metadataContent)
		tw.Close()

		_, err := ParseBundleFromTarball(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("missing metadata createAt", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		baseCRLHeader := &tar.Header{
			Name:    "base.crl",
			Size:    int64(len(crlBytes)),
			Mode:    0644,
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(baseCRLHeader); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write(crlBytes)

		metadataContent := []byte(`{"base.crl": {"url": "https://example.com/base.crl"}}`)
		metadataHeader := &tar.Header{
			Name:    "metadata.json",
			Size:    int64(len(metadataContent)),
			Mode:    0644,
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(metadataHeader); err != nil {
			t.Fatalf("failed to write header: %v", err)
		}
		tw.Write(metadataContent)
		tw.Close()

		_, err := ParseBundleFromTarball(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestSaveAsTarballFailed(t *testing.T) {
	t.Run("validate failed", func(t *testing.T) {
		bundle := &Bundle{}
		if err := bundle.SaveAsTarball(&errorWriter{}); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	certChain := testhelper.GetRevokableRSAChainWithRevocations(2, false, true)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1),
	}, certChain[1].Cert, certChain[1].PrivateKey)
	if err != nil {
		t.Fatalf("failed to create base CRL: %v", err)
	}

	t.Run("write base CRL to tarball failed", func(t *testing.T) {
		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			t.Fatalf("failed to parse base CRL: %v", err)
		}
		bundle, err := NewBundle(crl, "https://example.com/base.crl")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if err := bundle.SaveAsTarball(&errorWriter{}); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

type errorReader struct{}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, os.ErrNotExist
}

type errorWriter struct {
	Errors []error
	i      int
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	return 0, os.ErrNotExist
}
