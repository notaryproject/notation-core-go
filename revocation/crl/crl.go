package crl

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidFreshestCRL       = asn1.ObjectIdentifier{2, 5, 29, 46}
)

// Options specifies values that are needed to check OCSP revocation
type Options struct {
	CertChain  []*x509.Certificate
	HTTPClient *http.Client
	Cache      Cache
}

func CertCheckStatus(cert, issuer *x509.Certificate, opts Options) *result.CertRevocationResult {
	if opts.Cache == nil {
		return &result.CertRevocationResult{Error: errors.New("cache is required")}
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	if !HasCRL(cert) {
		return &result.CertRevocationResult{Error: errors.New("certificate does not support CRL")}
	}

	crlClient := NewCRLClient(opts.Cache, opts.HTTPClient)

	// Check CRL
	var lastError error
	for _, crlURL := range cert.CRLDistributionPoints {
		crl, err := crlClient.Fetch(crlURL)
		if err != nil {
			lastError = err
			continue
		}

		err = validateCRL(crl, issuer)
		if err != nil {
			lastError = err
			continue
		}

		// check revocation
		for _, revokedCert := range crl.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return &result.CertRevocationResult{
					Result:    result.ResultRevoked,
					CRLStatus: result.NewCRLStatus(revokedCert),
				}
			}
		}

		return &result.CertRevocationResult{
			Result: result.ResultOK,
		}
	}

	return &result.CertRevocationResult{Result: result.ResultNonRevokable, Error: lastError}
}

func validateCRL(crl *x509.RevocationList, issuer *x509.Certificate) error {
	// check crl expiration
	if time.Now().After(crl.NextUpdate) {
		return errors.New("CRL is expired")
	}

	// check signature
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL signature verification failed: %v", err)
	}

	// check extensions
	for _, ext := range crl.Extensions {
		if ext.Critical {
			return fmt.Errorf("CRL contains unsupported critical extension: %v", ext.Id)
		}

		// check freshest CRL
		if ext.Id.Equal(oidFreshestCRL) {

		}
	}

	return nil
}

func deltaCRL(crl *x509.RevocationList, issuer *x509.Certificate, crlClient CRLClient) (*x509.RevocationList, error) {
	for _, ext := range crl.Extensions {
		if ext.Id.Equal(oidFreshestCRL) {
			url := string(ext.Value)
			deltaCDPs, err := parseCDP(ext)
			if err != nil {
				return nil, err
			}

			for _, deltaCDP := range deltaCDPs {

				deltaCRL, err := crlClient.Fetch(url)
				if err != nil {
					return nil, err
				}

				if err := validateCRL(deltaCRL, issuer); err != nil {
					return nil, err
				}

				if err := validateDeltaCRL(deltaCRL, crl); err != nil {
					return nil, err
				}
				return deltaCRL, nil

			}
		}
	}
	return nil, noDeltaCRL{}
}

func parseCDP(ext pkix.Extension) ([]string, error) {
	var deltaCDPs []string
	// RFC 5280, 4.2.1.13

	// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
	//
	// DistributionPoint ::= SEQUENCE {
	//     distributionPoint       [0]     DistributionPointName OPTIONAL,
	//     reasons                 [1]     ReasonFlags OPTIONAL,
	//     cRLIssuer               [2]     GeneralNames OPTIONAL }
	//
	// DistributionPointName ::= CHOICE {
	//     fullName                [0]     GeneralNames,
	//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
	val := cryptobyte.String(ext.Value)
	if !val.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid CRL distribution points")
	}
	for !val.Empty() {
		var dpDER cryptobyte.String
		if !val.ReadASN1(&dpDER, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("x509: invalid CRL distribution point")
		}
		var dpNameDER cryptobyte.String
		var dpNamePresent bool
		if !dpDER.ReadOptionalASN1(&dpNameDER, &dpNamePresent, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("x509: invalid CRL distribution point")
		}
		if !dpNamePresent {
			continue
		}
		if !dpNameDER.ReadASN1(&dpNameDER, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("x509: invalid CRL distribution point")
		}
		for !dpNameDER.Empty() {
			if !dpNameDER.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
				break
			}
			var uri cryptobyte.String
			if !dpNameDER.ReadASN1(&uri, cryptobyte_asn1.Tag(6).ContextSpecific()) {
				return nil, errors.New("x509: invalid CRL distribution point")
			}
			deltaCDPs = append(deltaCDPs, string(uri))
		}
	}

	return deltaCDPs, nil
}

// Reference: https://tools.ietf.org/html/rfc5280#section-5.2.4
func validateDeltaCRL(deltaCRL *x509.RevocationList, crl *x509.RevocationList) error {
	for _, ext := range deltaCRL.Extensions {
		if ext.Id.Equal(oidDeltaCRLIndicator) {
			// check critical
			if !ext.Critical {
				return errors.New("delta CRL is not critical")
			}

			// check base CRL number
			baseCRLNumber := new(big.Int)
			if _, err := asn1.Unmarshal(ext.Value, baseCRLNumber); err != nil {
				return fmt.Errorf("failed to parse base CRL number: %v", err)
			}
			if crl.Number.Cmp(baseCRLNumber) >= 0 {
				return staledDeltaCRL{}
			}

			// TODO: verify issuingDistributionPoint

			// check issuer
			if deltaCRL.Issuer.CommonName != crl.Issuer.CommonName {
				return fmt.Errorf("delta CRL issuer is not the same as the base CRL issuer: %s != %s", deltaCRL.Issuer.CommonName, crl.Issuer.CommonName)
			}
			if !bytes.Equal(crl.AuthorityKeyId, deltaCRL.AuthorityKeyId) {
				return errors.New("delta CRL is not valid")
			}

			return nil
		}
	}
	return errors.New("delta CRL is not valid")
}

// HasCRL checks if the certificate supports CRL.
func HasCRL(cert *x509.Certificate) bool {
	return len(cert.CRLDistributionPoints) > 0
}
