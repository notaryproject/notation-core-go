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
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/internal/oid"
)

// ValidateCodeSigningCertChain takes an ordered code signing certificate chain
// and validates issuance from leaf to root
// Validates certificates according to this spec:
// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#certificate-requirements
func ValidateCodeSigningCertChain(certChain []*x509.Certificate, signingTime *time.Time) error {
	if len(certChain) < 1 {
		return errors.New("certificate chain must contain at least one certificate")
	}

	// For self-signed signing certificate (not a CA)
	if len(certChain) == 1 {
		cert := certChain[0]
		if err := validateSelfSignedLeaf(cert); err != nil {
			return err
		}
		if signedTimeError := validateSigningTime(cert, signingTime); signedTimeError != nil {
			return signedTimeError
		}
		if err := validateCodeSigningLeafCertificate(cert); err != nil {
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
			if err := validateCodeSigningLeafCertificate(cert); err != nil {
				return err
			}
		} else {
			if err := validateCodeSigningCACertificate(cert, i-1); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCodeSigningCACertificate(cert *x509.Certificate, expectedPathLen int) error {
	if err := validateCABasicConstraints(cert, expectedPathLen); err != nil {
		return err
	}
	return validateCodeSigningCAKeyUsage(cert)
}

func validateCodeSigningLeafCertificate(cert *x509.Certificate) error {
	if err := validateLeafBasicConstraints(cert); err != nil {
		return err
	}
	if err := validateCodeSigningLeafKeyUsage(cert); err != nil {
		return err
	}
	if err := validateCodeSigningExtendedKeyUsage(cert); err != nil {
		return err
	}
	return validateSignatureAlgorithm(cert)
}

func validateCodeSigningCAKeyUsage(cert *x509.Certificate) error {
	if err := validateCodeSigningKeyUsagePresent(cert); err != nil {
		return err
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate with subject %q: key usage must have the bit positions for key cert sign set", cert.Subject)
	}
	return nil
}

func validateCodeSigningLeafKeyUsage(cert *x509.Certificate) error {
	if err := validateCodeSigningKeyUsagePresent(cert); err != nil {
		return err
	}
	return validateLeafKeyUsage(cert)
}

func validateCodeSigningKeyUsagePresent(cert *x509.Certificate) error {
	var hasKeyUsageExtension bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid.KeyUsage) {
			if !ext.Critical {
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

func validateCodeSigningExtendedKeyUsage(cert *x509.Certificate) error {
	if len(cert.ExtKeyUsage) == 0 {
		return nil
	}

	excludedEkus := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning,
	}

	for _, certEku := range cert.ExtKeyUsage {
		for _, excludedEku := range excludedEkus {
			if certEku == excludedEku {
				return fmt.Errorf("certificate with subject %q: extended key usage must not contain %s eku", cert.Subject, ekuToString(excludedEku))
			}
		}
	}
	return nil
}
