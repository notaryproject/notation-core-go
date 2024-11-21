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
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

func isSelfSigned(cert *x509.Certificate) (bool, error) {
	return isIssuedBy(cert, cert)
}

func isIssuedBy(subject *x509.Certificate, issuer *x509.Certificate) (bool, error) {
	if err := subject.CheckSignatureFrom(issuer); err != nil {
		return false, err
	}
	return bytes.Equal(issuer.RawSubject, subject.RawIssuer), nil
}

func validateSigningTime(cert *x509.Certificate, signingTime *time.Time) error {
	if signingTime != nil && (signingTime.Before(cert.NotBefore) || signingTime.After(cert.NotAfter)) {
		return fmt.Errorf("certificate with subject %q was invalid at signing time of %s. Certificate is valid from [%s] to [%s]",
			cert.Subject, signingTime.UTC(), cert.NotBefore.UTC(), cert.NotAfter.UTC())
	}
	return nil
}

func validateCABasicConstraints(cert *x509.Certificate, expectedPathLen int) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return fmt.Errorf("certificate with subject %q: ca field in basic constraints must be present, critical, and set to true", cert.Subject)
	}
	maxPathLen := cert.MaxPathLen
	isMaxPathLenPresent := maxPathLen > 0 || (maxPathLen == 0 && cert.MaxPathLenZero)
	if isMaxPathLenPresent && maxPathLen < expectedPathLen {
		return fmt.Errorf("certificate with subject %q: expected path length of %d but certificate has path length %d instead", cert.Subject, expectedPathLen, maxPathLen)
	}
	return nil
}

func validateLeafBasicConstraints(cert *x509.Certificate) error {
	if cert.BasicConstraintsValid && cert.IsCA {
		return fmt.Errorf("certificate with subject %q: if the basic constraints extension is present, the ca field must be set to false", cert.Subject)
	}
	return nil
}

func validateLeafKeyUsage(cert *x509.Certificate) error {
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("the certificate with subject %q is invalid. The key usage must have the bit positions for \"Digital Signature\" set", cert.Subject)
	}

	var invalidKeyUsages []string
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		invalidKeyUsages = append(invalidKeyUsages, `"KeyEncipherment"`)
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		invalidKeyUsages = append(invalidKeyUsages, `"DataEncipherment"`)
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		invalidKeyUsages = append(invalidKeyUsages, `"KeyAgreement"`)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		invalidKeyUsages = append(invalidKeyUsages, `"CertSign"`)
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		invalidKeyUsages = append(invalidKeyUsages, `"CRLSign"`)
	}
	if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		invalidKeyUsages = append(invalidKeyUsages, `"EncipherOnly"`)
	}
	if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		invalidKeyUsages = append(invalidKeyUsages, `"DecipherOnly"`)
	}
	if len(invalidKeyUsages) > 0 {
		return fmt.Errorf("the certificate with subject %q is invalid. The key usage must be \"Digital Signature\" only, but found %s", cert.Subject, strings.Join(invalidKeyUsages, ", "))
	}
	return nil
}

func validateSignatureAlgorithm(cert *x509.Certificate) error {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		switch bitSize := key.Size() << 3; bitSize {
		case 2048, 3072, 4096:
			return nil
		default:
			return fmt.Errorf("certificate with subject %q: rsa key size %d bits is not supported", cert.Subject, bitSize)
		}
	case *ecdsa.PublicKey:
		switch bitSize := key.Curve.Params().BitSize; bitSize {
		case 256, 384, 521:
			return nil
		default:
			return fmt.Errorf("certificate with subject %q: ecdsa key size %d bits is not supported", cert.Subject, bitSize)
		}
	}
	return fmt.Errorf("certificate with subject %q: unsupported public key type", cert.Subject)
}

func ekuToString(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageTimeStamping:
		return "Timestamping"
	default:
		return fmt.Sprintf("%d", int(eku))
	}
}
