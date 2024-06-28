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
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestValidTimestampingChain(t *testing.T) {
	timestamp_leaf, err := readSingleCertificate("testdata/timestamp_leaf.crt")
	if err != nil {
		t.Fatal(err)
	}
	timestamp_intermediate, err := readSingleCertificate("testdata/timestamp_intermediate.crt")
	if err != nil {
		t.Fatal(err)
	}
	timestamp_root, err := readSingleCertificate("testdata/timestamp_root.crt")
	if err != nil {
		t.Fatal(err)
	}

	certChain := []*x509.Certificate{timestamp_leaf, timestamp_intermediate, timestamp_root}
	signingTime := time.Now()

	err = ValidateTimestampingCertChain(certChain, &signingTime)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInvalidTimestampingChain(t *testing.T) {
	timestamp_leaf, err := readSingleCertificate("testdata/timestamp_leaf.crt")
	if err != nil {
		t.Fatal(err)
	}
	timestamp_intermediate, err := readSingleCertificate("testdata/timestamp_intermediate.crt")
	if err != nil {
		t.Fatal(err)
	}
	timestamp_root, err := readSingleCertificate("testdata/timestamp_root.crt")
	if err != nil {
		t.Fatal(err)
	}

	signingTime := time.Now()
	expectedErr := "certificate chain must contain at least one certificate"
	err = ValidateTimestampingCertChain([]*x509.Certificate{}, &signingTime)
	assertErrorEqual(expectedErr, err, t)

	certChain := []*x509.Certificate{timestamp_leaf, intermediateCert2, intermediateCert1, rootCert}
	expectedErr = "invalid certificates or certificate with subject \"CN=DigiCert Timestamp 2023,O=DigiCert\\\\, Inc.,C=US\" is not issued by \"CN=Intermediate2\". Error: crypto/rsa: verification error"
	err = ValidateTimestampingCertChain(certChain, &signingTime)
	assertErrorEqual(expectedErr, err, t)

	certChain = []*x509.Certificate{timestamp_leaf}
	expectedErr = "certificate with subject \"CN=DigiCert Timestamp 2023,O=DigiCert\\\\, Inc.,C=US\" was invalid at signing time of 2000-09-17 14:09:10 +0000 UTC. Certificate is valid from [2023-07-14 00:00:00 +0000 UTC] to [2034-10-13 23:59:59 +0000 UTC]"
	dummySigningTime := time.Date(2000, time.September, 17, 14, 9, 10, 0, time.UTC)
	err = ValidateTimestampingCertChain(certChain, &dummySigningTime)
	assertErrorEqual(expectedErr, err, t)

	certChain = []*x509.Certificate{timestamp_leaf}
	expectedErr = "invalid self-signed certificate. subject: \"CN=DigiCert Timestamp 2023,O=DigiCert\\\\, Inc.,C=US\". Error: crypto/rsa: verification error"
	err = ValidateTimestampingCertChain(certChain, &signingTime)
	assertErrorEqual(expectedErr, err, t)

	certChain = []*x509.Certificate{timestamp_leaf, timestamp_intermediate, timestamp_root}
	expectedErr = "certificate with subject \"CN=DigiCert Timestamp 2023,O=DigiCert\\\\, Inc.,C=US\" was invalid at signing time of 2000-09-17 14:09:10 +0000 UTC. Certificate is valid from [2023-07-14 00:00:00 +0000 UTC] to [2034-10-13 23:59:59 +0000 UTC]"
	dummySigningTime = time.Date(2000, time.September, 17, 14, 9, 10, 0, time.UTC)
	err = ValidateTimestampingCertChain(certChain, &dummySigningTime)
	assertErrorEqual(expectedErr, err, t)

	certChain = []*x509.Certificate{timestamp_leaf, timestamp_intermediate}
	expectedErr = "root certificate with subject \"CN=DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA,O=DigiCert\\\\, Inc.,C=US\" is invalid or not self-signed. Certificate chain must end with a valid self-signed root certificate. Error: crypto/rsa: verification error"
	err = ValidateTimestampingCertChain(certChain, &signingTime)
	assertErrorEqual(expectedErr, err, t)

	certChain = []*x509.Certificate{timestamp_root, timestamp_root}
	expectedErr = "leaf certificate with subject \"CN=DigiCert Trusted Root G4,OU=www.digicert.com,O=DigiCert Inc,C=US\" is self-signed. Certificate chain must not contain self-signed leaf certificate"
	err = ValidateTimestampingCertChain(certChain, &signingTime)
	assertErrorEqual(expectedErr, err, t)

	certChain = []*x509.Certificate{timestamp_leaf, timestamp_intermediate, timestamp_root, timestamp_root}
	expectedErr = "intermediate certificate with subject \"CN=DigiCert Trusted Root G4,OU=www.digicert.com,O=DigiCert Inc,C=US\" is self-signed. Certificate chain must not contain self-signed intermediate certificate"
	err = ValidateTimestampingCertChain(certChain, &signingTime)
	assertErrorEqual(expectedErr, err, t)
}

var ekuNonCriticalTimeLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC5TCCAc2gAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1JbnRl\n" +
	"cm1lZGlhdGUyMCAXDTIyMDYzMDE5MjAwNFoYDzMwMjExMDMxMTkyMDA0WjAbMRkw\n" +
	"FwYDVQQDDBBUaW1lU3RhbXBpbmdMZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
	"MIIBCgKCAQEAyx2ispY5C5sQCiLAuCUTp4wv+fpgHwzE4an8eqi+Jrm0tEabTdzP\n" +
	"IdZFRYPZbgRx+D9DKeN76f+rt51G9gOX77fYWyIXgnVL4UAYNlQj58hqZ0IO22vT\n" +
	"nIFiDbJoSPuamQaLZNuluiirUwJv1uqSQiEnWHC4LhKwNOo4UHH5S3XkkYRpdFBF\n" +
	"Tm4uOTaQJA9dfCh+0wbe7ZlEjDiuk1GTSQu69EPIl4IK7aEWqdvk2z1Pg4YkgJZX\n" +
	"mWzkECNayUiBeHj7lL5ZnyZeki2l77WzXe/j5dgQ9E2+63hfBew+O/XeS/Tm/TyQ\n" +
	"0P8bQre6vbn9820Cpyg82fd1+5bwYedwVwIDAQABozUwMzAOBgNVHQ8BAf8EBAMC\n" +
	"B4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0B\n" +
	"AQsFAAOCAQEAB9Z80K17p4J3VCqVcKyhgkzzYPoKiBWFThVwxS2+TKY0x4zezSAT\n" +
	"69Nmf7NkVH4XyvCEUfgdWYst4t41rH3b5MTMOc5/nPeMccDWT0eZRivodF5hFWZd\n" +
	"2QSFiMHmfUhnglY0ocLbfKeI/QoSGiPyBWO0SK6qOszRi14lP0TpgvgNDtMY/Jj5\n" +
	"AyINT6o0tyYJvYE23/7ysT3U6pq50M4vOZiSuRys83As/qvlDIDKe8OVlDt6xRvr\n" +
	"fqdMFWSk6Iay2OCfYcjUbTutMzSI7dvhDivn5FKnNA6M7QD1lqb7V9fymgrQTsth\n" +
	"We9tUxypXgMjYN74QEHYxEAIfNOTeBppWw==\n" +
	"-----END CERTIFICATE-----"
var ekuNonCriticalTimeLeafCert = parseCertificateFromString(ekuNonCriticalTimeLeafPem)

func TestTimestampLeafWithNonCriticalEKU(t *testing.T) {
	expectedErr := "timestamp signing certificate with subject \"CN=TimeStampingLeaf\" must have extended key usage extension marked as critical"
	err := validateTimestampingLeafCertificate(ekuNonCriticalTimeLeafCert)
	assertErrorEqual(expectedErr, err, t)
}

var ekuWrongValuesTimeLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC6jCCAdKgAwIBAgIJAJOlT2AUbsZiMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAzMTcyM1oYDzIxMjIwNjAxMDMxNzIzWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOZe\n" +
	"9zjKWNlFD/HGrkaAI9mh9Fw1gF8S2tphQD/aPd9IS4HJJEQRkKz5oeHj2g1Y6TEk\n" +
	"plODrKlnoLe+ZFNFFD4xMVV55aQSJDTljCLPwIZt2VewlaAhIImYihOJvJFST1zW\n" +
	"K2NW4eLxt0awbE/YzL6beH4A6UsrcXcnN0KKiu6YD1/d5TezJoTQBMo6fboltuce\n" +
	"P/+RMxyqpvip7nyFF3Yrmhumb7DKJrmSfSjdziI5QoUqzqVgqJ8pXMRb3ZOKb499\n" +
	"d9RRxGkox93iOdSSlaP3FEl8VK9KqnD+MNhjVZbeYTfjm9UVdp91VLP1E/yfMXz+\n" +
	"fZhYkublK6v3GWSEcb0CAwEAAaNFMEMwDgYDVR0PAQH/BAQDAgeAMDEGA1UdJQQq\n" +
	"MCgGCCsGAQUFBwMIBggrBgEFBQcDAQYIKwYBBQUHAwQGCCsGAQUFBwMIMA0GCSqG\n" +
	"SIb3DQEBCwUAA4IBAQCaQZ+ws93F1azT6SKBYvBRBCj07+2DtNI83Q53GxrVy2vU\n" +
	"rP1ULX7beY87amy6kQcqnQ0QSaoLK+CDL88pPxR2PBzCauz70rMRY8O/KrrLcfwd\n" +
	"D5HM9DcbneqXQyfh0ZQpt0wK5wux0MFh2sAEv76jgYBMHq2zc+19skAW/oBtTUty\n" +
	"i/IdOVeO589KXwJzEJmKiswN9zKo9KGgAlKS05zohjv40AOCAs+8Q2lOJjRMq4Ji\n" +
	"z21qor5e/5+NnGY+2p4A7PbN+QnDdRC3y16dESRN50o5x6CwUWQO74+uRjrAWYCm\n" +
	"f/Y7qdOf5zZbY21n8KnLcFOsKhwv4t40Y/LQqN/L\n" +
	"-----END CERTIFICATE-----"
var ekuWrongValuesTimeLeaf = parseCertificateFromString(ekuWrongValuesTimeLeafPem)

func TestFailEkuWrongValuesTimeLeaf(t *testing.T) {
	err := validateTimestampingLeafCertificate(ekuWrongValuesTimeLeaf)
	assertErrorEqual("timestamp signing certificate with subject \"CN=Hello\" must have and only have Timestamping as extended key usage", err, t)
}

var ekuMissingTimestampingLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICzDCCAbSgAwIBAgIJAJtYOfTu82KRMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAzMTMxM1oYDzIxMjIwNjAxMDMxMzEzWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQN\n" +
	"GJKHE6cdcmrHkxXOTawWgYEF1X42IOK7gAXFg+KBPHPw4npDjUclLX0sY3XjBuhT\n" +
	"wI5DRATSNTV2ba3+DpFuH3D+Hbfjil91AG8XzormUPOOCbZqJxSKYAIZfPQGdUvV\n" +
	"UBulnbDsije00HoNZ03IvdjxbB/9y6a3qQEvIUaEjaZBH3s/YYQIiEmKu6eDpj3R\n" +
	"PnUcrP5b7jBMA/Vb8joLM0InzqGPRLPFAPf5womAjxZSsrgyVeA1xSm+6KtXMmaA\n" +
	"IKYwNVAOnhfqgUk0tlaRyXXji2T1M9w9l5XUA1iNOMcjTUTfFa5KW7c0TLTcK6vW\n" +
	"Eq1BEXUEw7HP7DQUjycCAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM\n" +
	"MAoGCCsGAQUFBwMJMA0GCSqGSIb3DQEBCwUAA4IBAQCSr6A/YAMd6lisgipR0UCA\n" +
	"4Ye/1kl0jglT7stLTfftSeXgCKXYlwus9VSpZBtg+RvJkihlLNT6vtsiTMfJUBBc\n" +
	"jALLKYUQuCw9sReAbfvecIfc2bUve6X8isLWDVnxlC1udx2WG3lIfW2Sgs/dYeZW\n" +
	"yqLTagK5GLlDfg9gBpHLmQYOmshhI85ObOioUAiWTW+S6mx4Bphgl7dlcUabJxEJ\n" +
	"MpJJiGPkUUUCuYkp31E7S4JRbSXSkaHefZxB5fvhlbnACeqnOtMG/IKaTjCUemkK\n" +
	"ZRmJ0Al1PTWs+Dn8zLzexP/LkmQZU/FUMxeat/dAnc2blDbVnAsvcvnutXGHoZH5\n" +
	"-----END CERTIFICATE-----"
var ekuMissingTimestampingLeaf = parseCertificateFromString(ekuMissingTimestampingLeafPem)

func TestFailEkuMissingTimestampingLeaf(t *testing.T) {
	err := validateTimestampingLeafCertificate(ekuMissingTimestampingLeaf)
	assertErrorEqual("timestamp signing certificate with subject \"CN=Hello\" must have and only have Timestamping as extended key usage", err, t)
}

func TestTimestampingFailNoBasicConstraintsCa(t *testing.T) {
	err := validateTimestampingCACertificate(noBasicConstraintsCa, 3)
	assertErrorEqual("certificate with subject \"CN=Hello\": ca field in basic constraints must be present, critical, and set to true", err, t)
}

func TestTimestampingFailKuMissingCa(t *testing.T) {
	err := validateTimestampingCACertificate(kuMissingCa, 3)
	assertErrorEqual("certificate with subject \"CN=Hello\": key usage extension must be present", err, t)
}

func TestTimestampingFailInvalidPathLenCa(t *testing.T) {
	err := validateTimestampingCACertificate(rootCert, 3)
	assertErrorEqual("certificate with subject \"CN=Root\": expected path length of 3 but certificate has path length 2 instead", err, t)
}

func TestTimestampingFailKuNotCertSignCa(t *testing.T) {
	err := validateTimestampingCACertificate(kuNotCertSignCa, 3)
	assertErrorEqual("certificate with subject \"CN=Hello\": key usage must have the bit positions for key cert sign set", err, t)
}

func TestTimestampingFailWrongExtendedKeyUsage(t *testing.T) {
	err := validateTimestampingLeafCertificate(validNoOptionsLeaf)
	assertErrorEqual("timestamp signing certificate with subject \"CN=Hello\" must have and only have Timestamping as extended key usage", err, t)
}

func TestValidateTimestampingLeafCertificate(t *testing.T) {
	err := validateTimestampingLeafCertificate(caTrueLeaf)
	assertErrorEqual("certificate with subject \"CN=Hello\": if the basic constraints extension is present, the ca field must be set to false", err, t)

	err = validateTimestampingLeafCertificate(kuNoDigitalSignatureLeaf)
	assertErrorEqual("the certificate with subject \"CN=Hello\" is invalid. The key usage must have the bit positions for \"Digital Signature\" set", err, t)

	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "Test CN"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	err = validateTimestampingLeafCertificate(cert)
	assertErrorEqual("certificate with subject \"CN=Test CN\": key usage extension must be present", err, t)
}

func TestEkuToString(t *testing.T) {
	if ekuToString(x509.ExtKeyUsageAny) != "Any" {
		t.Fatalf("expected Any")
	}
	if ekuToString(x509.ExtKeyUsageClientAuth) != "ClientAuth" {
		t.Fatalf("expected ClientAuth")
	}
	if ekuToString(x509.ExtKeyUsageEmailProtection) != "EmailProtection" {
		t.Fatalf("expected EmailProtection")
	}
	if ekuToString(x509.ExtKeyUsageCodeSigning) != "CodeSigning" {
		t.Fatalf("expected CodeSigning")
	}
	if ekuToString(x509.ExtKeyUsageIPSECUser) != "7" {
		t.Fatalf("expected 7")
	}
}
