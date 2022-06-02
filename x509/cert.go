package x509

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ReadCertificateFile reads a certificate PEM file.
func ReadCertificateFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertificates(data)
}

// parseCertificates parses certificates from either PEM or DER data
// returns an empty list if no certificates are found
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	if block == nil {
		// data may be in DER format
		derCerts, err := x509.ParseCertificates(data)
		if err != nil {
			return nil, err
		}
		certs = append(certs, derCerts...)
	} else {
		// data is in PEM format
		for block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
			block, rest = pem.Decode(rest)
		}
	}

	return certs, nil
}

// ValidateCertChain takes an ordered certificate chain and validates issuance from leaf to root
func ValidateCertChain(certChain []*x509.Certificate) error {
	if len(certChain) < 2 {
		return errors.New("certificate chain must contain at least two certificates")
	}

	for i, cert := range certChain {
		if i == len(certChain)-1 {
			if !isSelfSigned(cert) {
				return errors.New("certificate chain must end with a root certificate (root certificates are self-signed)")
			}
		} else {
			if isSelfSigned(cert) {
				return errors.New("certificate chain must not contain self-signed intermediate certificates")
			} else if nextCert := certChain[i+1]; !isIssuedBy(cert, nextCert) {
				return fmt.Errorf("signature on certificate %q is not issued by %q", cert.Subject.String(), nextCert.Subject.String())
			}
		}
	}

	return nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return isIssuedBy(cert, cert)
}

func isIssuedBy(subject *x509.Certificate, issuer *x509.Certificate) bool {
	err := subject.CheckSignatureFrom(issuer)
	return err == nil && bytes.Equal(issuer.RawSubject, subject.RawIssuer)
}
