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

package cms

import (
	"crypto/x509"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestVerifySignedData(t *testing.T) {
	// parse signed data
	sigBytes, err := os.ReadFile("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal("failed to read test signature:", err)
	}
	signed, err := ParseSignedData(sigBytes)
	if err != nil {
		t.Fatal("ParseSignedData() error =", err)
	}

	// basic check on parsed signed data
	if got := len(signed.Certificates); got != 4 {
		t.Fatalf("len(Certificates) = %v, want %v", got, 4)
	}
	if got := len(signed.SignerInfos); got != 1 {
		t.Fatalf("len(Signers) = %v, want %v", got, 1)
	}

	// verify with no root CAs and should fail
	roots := x509.NewCertPool()
	opts := x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if _, err := signed.Verify(opts); err == nil {
		t.Errorf("ParseSignedData.Verify() error = %v, wantErr %v", err, true)
	} else if vErr, ok := err.(VerificationError); !ok {
		t.Errorf("ParseSignedData.Verify() error = %v, want VerificationError", err)
	} else if _, ok := vErr.Detail.(x509.UnknownAuthorityError); !ok {
		t.Errorf("ParseSignedData.Verify() VerificationError.Detail = %v, want UnknownAuthorityError", err)
	}

	// verify with proper root CA
	rootCABytes, err := os.ReadFile("testdata/GlobalSignRootCA.crt")
	if err != nil {
		t.Fatal("failed to read root CA certificate:", err)
	}
	if ok := roots.AppendCertsFromPEM(rootCABytes); !ok {
		t.Fatal("failed to load root CA certificate")
	}
	verifiedSigners, err := signed.Verify(opts)
	if err != nil {
		t.Fatal("ParseSignedData.Verify() error =", err)
	}
	if !reflect.DeepEqual(verifiedSigners, signed.Certificates[:1]) {
		t.Fatalf("ParseSignedData.Verify() = %v, want %v", verifiedSigners, signed.Certificates[:1])
	}
}

func TestParseSignedData(t *testing.T) {
	t.Run("invalid berData", func(t *testing.T) {
		_, err := ParseSignedData([]byte("invalid"))
		if err == nil {
			t.Fatal("ParseSignedData() error = nil, wantErr true")
		}
	})

	t.Run("invalid contentInfo", func(t *testing.T) {
		_, err := ParseSignedData([]byte{0x30, 0x00})
		if err == nil {
			t.Fatal("ParseSignedData() error = nil, wantErr true")
		}
	})

	t.Run("content type is not signed data", func(t *testing.T) {
		_, err := ParseSignedData([]byte{
			0x30, 0x12, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x06, 0xa0, 0x03, 0x04, 0x01, 0x78,
		})
		if err != ErrNotSignedData {
			t.Errorf("ParseSignedData() error = %v, wantErr %v", err, ErrNotSignedData)
		}
	})

	t.Run("invalid signed data content", func(t *testing.T) {
		_, err := ParseSignedData([]byte{
			0x30, 0x10, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x03, 0x04, 0x01, 0x78,
		})
		fmt.Println(err)
		if err == nil {
			t.Fatal("ParseSignedData() error = nil, wantErr true")
		}
	})

	t.Run("invalid certificate", func(t *testing.T) {
		// parse signed data
		sigBytes, err := os.ReadFile("testdata/TimeStampTokenWithInvalidCertificates.p7s")
		if err != nil {
			t.Fatal("failed to read test signature:", err)
		}
		_, err = ParseSignedData(sigBytes)
		if err == nil {
			t.Fatal("ParseSignedData() error = nil, wantErr true")
		}
	})
}

func TestVerify(t *testing.T) {

	testData := []struct {
		name     string
		filePath string
		wantErr  bool
	}{
		{
			name:     "without certificate",
			filePath: "testdata/TimeStampTokenWithoutCertificate.p7s",
			wantErr:  true,
		},
		{
			name:     "without signer info",
			filePath: "testdata/TimeStampTokenWithoutSigner.p7s",
			wantErr:  true,
		},
		{
			name:     "signer version is 2",
			filePath: "testdata/TimeStampTokenWithSignerVersion2.p7s",
			wantErr:  true,
		},
	}

	for _, testcase := range testData {
		t.Run(testcase.name, func(t *testing.T) {
			// parse signed data
			sigBytes, err := os.ReadFile(testcase.filePath)
			if err != nil {
				t.Fatal("failed to read test signature:", err)
			}
			signed, err := ParseSignedData(sigBytes)
			if err != nil {
				t.Fatal("ParseSignedData() error =", err)
			}

			// verify with no root CAs and should fail
			roots := x509.NewCertPool()
			opts := x509.VerifyOptions{
				Roots:       roots,
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
				CurrentTime: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
			}
			if _, err := signed.Verify(opts); err == nil {
				t.Errorf("ParseSignedData.Verify() error = %v, wantErr %v", err, true)
			}
		})
	}
}

func TestVerifyCorruptedSignedData(t *testing.T) {
	// parse signed data
	sigBytes, err := os.ReadFile("testdata/TimeStampToken.p7s")
	if err != nil {
		t.Fatal("failed to read test signature:", err)
	}
	signed, err := ParseSignedData(sigBytes)
	if err != nil {
		t.Fatal("ParseSignedData() error =", err)
	}

	// corrupt the content
	signed.Content = []byte("corrupted data")

	// verify with no root CAs and should fail
	roots := x509.NewCertPool()
	rootCABytes, err := os.ReadFile("testdata/GlobalSignRootCA.crt")
	if err != nil {
		t.Fatal("failed to read root CA certificate:", err)
	}
	if ok := roots.AppendCertsFromPEM(rootCABytes); !ok {
		t.Fatal("failed to load root CA certificate")
	}
	opts := x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if _, err := signed.Verify(opts); err == nil {
		t.Errorf("ParseSignedData.Verify() error = %v, wantErr %v", err, true)
	} else if _, ok := err.(VerificationError); !ok {
		t.Errorf("ParseSignedData.Verify() error = %v, want VerificationError", err)
	}
}
