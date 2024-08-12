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

package cache

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/testhelper"
)

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
		_, err := parseBundleFromTar(bytes.NewReader(buf.Bytes()))
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

		_, err := parseBundleFromTar(bytes.NewReader(buf.Bytes()))
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

		_, err := parseBundleFromTar(bytes.NewReader(buf.Bytes()))
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}
