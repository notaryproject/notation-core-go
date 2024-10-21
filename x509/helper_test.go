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

package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/internal/oid"
)

func createSelfSignedCert(subject string, issuer string, isTimestamp bool) (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if isTimestamp {
		oids := []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}
		value, err := asn1.Marshal(oids)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = []pkix.Extension{{
			Id:       oid.ExtKeyUsage,
			Critical: true,
			Value:    value,
		}}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}

	parentTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: issuer},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parentTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func TestValidateSelfSignedLeaf(t *testing.T) {
	selfSignedCert, err := createSelfSignedCert("Valid Cert", "Valid Cert", false)
	if err != nil {
		t.Fatalf("failed to create valid self-signed certificate: %v", err)
	}
	emptyCert := &x509.Certificate{}
	notSelfIssuedCert, err := createSelfSignedCert("Not Self Issued Cert", "Invalid Issuer", false)
	if err != nil {
		t.Fatalf("failed to create not self-issued certificate: %v", err)
	}

	tests := []struct {
		name    string
		cert    *x509.Certificate
		wantErr bool
	}{
		{
			name:    "Valid Self-Signed Certificate",
			cert:    selfSignedCert,
			wantErr: false,
		},
		{
			name:    "Empty Certificate",
			cert:    emptyCert,
			wantErr: true,
		},
		{
			name:    "Not Self-Issued Certificate",
			cert:    notSelfIssuedCert,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSelfSignedLeaf(tt.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSelfSignedLeaf() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

}
