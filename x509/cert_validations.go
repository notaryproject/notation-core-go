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
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
)

// ValidateCodeSigningCertChain takes an ordered code-signing certificate chain
// and validates issuance from leaf to root
// Validates certificates according to this spec:
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#certificate-requirements
func ValidateCodeSigningCertChain(certChain []*x509.Certificate, signingTime *time.Time) error {
	return validateCertChain(certChain, 0, signingTime, false)
}

// ValidateTimeStampingCertChain takes an ordered time-stamping certificate
// chain and validates issuance from leaf to root
// Validates certificates according to this spec:
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#certificate-requirements
func ValidateTimeStampingCertChain(certChain []*x509.Certificate, signingTime *time.Time) error {
	return validateCertChain(certChain, x509.ExtKeyUsageTimeStamping, signingTime, true)
}

// ValidateTimestampingSigningCeritifcate validates the signing certificate of
// a timestamp token.
// Reference: https://github.com/notaryproject/specifications/blob/v1.0.0/specs/signature-specification.md#leaf-certificates
func ValidateTimestampingSigningCeritifcate(signingCert *x509.Certificate, signingTime *time.Time) error {
	if signedTimeError := validateSigningTime(signingCert, signingTime); signedTimeError != nil {
		return signedTimeError
	}
	return validateLeafCertificate(signingCert, x509.ExtKeyUsageTimeStamping)
}

func validateCertChain(certChain []*x509.Certificate, expectedLeafEku x509.ExtKeyUsage, signingTime *time.Time, timestamp bool) error {
	if len(certChain) < 1 {
		return errors.New("certificate chain must contain at least one certificate")
	}

	// For self-signed signing certificate (not a CA)
	if len(certChain) == 1 {
		cert := certChain[0]
		if signedTimeError := validateSigningTime(cert, signingTime); signedTimeError != nil {
			return signedTimeError
		}
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			return fmt.Errorf("invalid self-signed certificate. subject: %q. Error: %w", cert.Subject, err)
		}
		if err := validateLeafCertificate(cert, expectedLeafEku); err != nil {
			return fmt.Errorf("invalid self-signed certificate. Error: %w", err)
		}
		return nil
	}

	for i, cert := range certChain {
		if signedTimeError := validateSigningTime(cert, signingTime); signedTimeError != nil {
			return signedTimeError
		}
		if i == len(certChain)-1 {
			selfSigned, selfSignedError := isSelfSigned(cert)
			if selfSignedError != nil {
				return fmt.Errorf("root certificate with subject %q is invalid or not self-signed. Certificate chain must end with a valid self-signed root certificate. Error: %v", cert.Subject, selfSignedError)
			}
			if !selfSigned {
				return fmt.Errorf("root certificate with subject %q is not self-signed. Certificate chain must end with a valid self-signed root certificate", cert.Subject)
			}
		} else {
			// This is to avoid extra/redundant multiple root cert at the end
			// of certificate-chain
			selfSigned, selfSignedError := isSelfSigned(cert)
			// not checking selfSignedError != nil here because we expect
			// a non-nil err. For a non-root certificate, it shouldn't be
			// self-signed, hence CheckSignatureFrom would return a non-nil
			// error.
			if selfSignedError == nil && selfSigned {
				if i == 0 {
					return fmt.Errorf("leaf certificate with subject %q is self-signed. Certificate chain must not contain self-signed leaf certificate", cert.Subject)
				}
				return fmt.Errorf("intermediate certificate with subject %q is self-signed. Certificate chain must not contain self-signed intermediate certificate", cert.Subject)
			}
			parentCert := certChain[i+1]
			issuedBy, issuedByError := isIssuedBy(cert, parentCert)
			if issuedByError != nil {
				return fmt.Errorf("invalid certificates or certificate with subject %q is not issued by %q. Error: %v", cert.Subject, parentCert.Subject, issuedByError)
			}
			if !issuedBy {
				return fmt.Errorf("certificate with subject %q is not issued by %q", cert.Subject, parentCert.Subject)
			}
		}

		if i == 0 {
			if err := validateLeafCertificate(cert, expectedLeafEku); err != nil {
				return err
			}
		} else {
			if err := validateCACertificate(cert, i-1, timestamp); err != nil {
				return err
			}
		}
	}
	return nil
}

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

func validateCACertificate(cert *x509.Certificate, expectedPathLen int, timestamp bool) error {
	if err := validateCABasicConstraints(cert, expectedPathLen); err != nil {
		return err
	}
	return validateCAKeyUsage(cert, timestamp)
}

func validateLeafCertificate(cert *x509.Certificate, expectedEku x509.ExtKeyUsage) error {
	if err := validateLeafBasicConstraints(cert); err != nil {
		return err
	}
	if err := validateLeafKeyUsage(cert, expectedEku == x509.ExtKeyUsageTimeStamping); err != nil {
		return err
	}
	if err := validateExtendedKeyUsage(cert, expectedEku); err != nil {
		return err
	}
	return validateSignatureAlgorithm(cert)
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

func validateCAKeyUsage(cert *x509.Certificate, timestamp bool) error {
	if err := validateKeyUsagePresent(cert, timestamp); err != nil {
		return err
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate with subject %q: key usage must have the bit positions for key cert sign set", cert.Subject)
	}
	return nil
}

func validateLeafKeyUsage(cert *x509.Certificate, timestamp bool) error {
	if err := validateKeyUsagePresent(cert, timestamp); err != nil {
		return err
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("the certificate with subject %q is invalid. The key usage must have the bit positions for \"Digital Signature\" set", cert.Subject)
	}

	var invalidKeyUsages []string
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		invalidKeyUsages = append(invalidKeyUsages, `"ContentCommitment"`)
	}
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

func validateKeyUsagePresent(cert *x509.Certificate, timestamp bool) error {
	keyUsageExtensionOid := asn1.ObjectIdentifier{2, 5, 29, 15}

	var hasKeyUsageExtension bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(keyUsageExtensionOid) {
			if !ext.Critical && !timestamp {
				return fmt.Errorf("certificate with subject %q: key usage extension must be marked critical", cert.Subject)
			}
			hasKeyUsageExtension = true
			break
		}
	}
	if !hasKeyUsageExtension {
		return fmt.Errorf("certificate with subject %q: key usage extension must be present", cert.Subject)
	}
	return nil
}

func validateExtendedKeyUsage(cert *x509.Certificate, expectedEku x509.ExtKeyUsage) error {
	extKeyUsageExtensionOid := asn1.ObjectIdentifier{2, 5, 29, 37}

	// cert is a timestamping certificate
	//
	// RFC 3161 2.3: The corresponding certificate MUST contain only one
	// instance of the extended key usage field extension. And it MUST be
	// marked as critical.
	if expectedEku == x509.ExtKeyUsageTimeStamping {
		if len(cert.ExtKeyUsage) != 1 ||
			cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping ||
			len(cert.UnknownExtKeyUsage) != 0 {
			return fmt.Errorf("timestamp signing certificate with subject %q must have and only have %s as extended key usage", cert.Subject, ekuToString(expectedEku))
		}
		// check if marked as critical
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(extKeyUsageExtensionOid) {
				if !ext.Critical {
					return fmt.Errorf("timestamp signing certificate with subject %q must have extended key usage extension marked as critical", cert.Subject)
				}
				break
			}
		}
		return nil
	}

	// cert is a codesigning certificate
	if len(cert.ExtKeyUsage) <= 0 {
		return nil
	}

	excludedEkus := []x509.ExtKeyUsage{
		x509.ExtKeyUsageAny,
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageOCSPSigning,
	}

	if expectedEku == 0 {
		excludedEkus = append(excludedEkus, x509.ExtKeyUsageTimeStamping)
	}

	var hasExpectedEku bool
	for _, certEku := range cert.ExtKeyUsage {
		if certEku == expectedEku {
			hasExpectedEku = true
			continue
		}
		for _, excludedEku := range excludedEkus {
			if certEku == excludedEku {
				return fmt.Errorf("certificate with subject %q: extended key usage must not contain %s eku", cert.Subject, ekuToString(excludedEku))
			}
		}
	}

	if expectedEku != 0 && !hasExpectedEku {
		return fmt.Errorf("certificate with subject %q: extended key usage must contain %s eku", cert.Subject, ekuToString(expectedEku))
	}
	return nil
}

func validateSignatureAlgorithm(cert *x509.Certificate) error {
	keySpec, err := signature.ExtractKeySpec(cert)
	if err != nil {
		return fmt.Errorf("certificate with subject %q: %w", cert.Subject, err)
	}
	if keySpec.SignatureAlgorithm() == 0 {
		return fmt.Errorf("certificate with subject %q: unsupported signature algorithm with key spec %+v", cert.Subject, keySpec)
	}
	return nil
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
		return "TimeStamping"
	default:
		return fmt.Sprintf("%d", int(eku))
	}
}
