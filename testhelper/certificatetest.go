// Package testhelper implements utility routines required for writing unit tests.
// The testhelper should only be used in unit tests.
package testhelper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

var (
	rsaRoot     RSACertTuple
	rsaLeaf     RSACertTuple
	ecdsaRoot   ECCertTuple
	ecdsaLeaf   ECCertTuple
	unsupported RSACertTuple
)

type RSACertTuple struct {
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

type ECCertTuple struct {
	Cert       *x509.Certificate
	PrivateKey *ecdsa.PrivateKey
}

// init runs before any other part of this package.
func init() {
	setupCertificates()
}

// GetRSARootCertificate returns root certificate signed using RSA algorithm
func GetRSARootCertificate() RSACertTuple {
	return rsaRoot
}

// GetRSALeafCertificate returns leaf certificate signed using RSA algorithm
func GetRSALeafCertificate() RSACertTuple {
	return rsaLeaf
}

// GetECRootCertificate returns root certificate signed using EC algorithm
func GetECRootCertificate() ECCertTuple {
	return ecdsaRoot
}

// GetECLeafCertificate returns leaf certificate signed using EC algorithm
func GetECLeafCertificate() ECCertTuple {
	return ecdsaLeaf
}

// GetUnsupportedCertificate returns certificate signed using RSA algorithm with key size of 1024 bits
// which is not supported by notary.
func GetUnsupportedCertificate() RSACertTuple {
	return unsupported
}

func setupCertificates() {
	rsaRoot = getCertTuple("Notation Test Root", nil)
	rsaLeaf = getCertTuple("Notation Test Leaf Cert", &rsaRoot)
	ecdsaRoot = getECCertTuple("Notation Test Root2", nil)
	ecdsaLeaf = getECCertTuple("Notation Test Leaf Cert", &ecdsaRoot)

	// This will be flagged by the static code analyzer as 'Use of a weak cryptographic key' but its intentional
	// and is used only for testing.
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	unsupported = GetRSACertTupleWithPK(k, "Notation Unsupported Root", nil)
}

func getCertTuple(cn string, issuer *RSACertTuple) RSACertTuple {
	pk, _ := rsa.GenerateKey(rand.Reader, 3072)
	return GetRSACertTupleWithPK(pk, cn, issuer)
}

func getECCertTuple(cn string, issuer *ECCertTuple) ECCertTuple {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return GetECDSACertTupleWithPK(k, cn, issuer)
}

func GetRSACertTupleWithPK(privKey *rsa.PrivateKey, cn string, issuer *RSACertTuple) RSACertTuple {
	template := getCertTemplate(issuer == nil, cn)

	var certBytes []byte
	if issuer != nil {
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, issuer.Cert, &privKey.PublicKey, issuer.PrivateKey)
	} else {
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	}

	cert, _ := x509.ParseCertificate(certBytes)
	return RSACertTuple{
		Cert:       cert,
		PrivateKey: privKey,
	}
}

func GetECDSACertTupleWithPK(privKey *ecdsa.PrivateKey, cn string, issuer *ECCertTuple) ECCertTuple {
	template := getCertTemplate(issuer == nil, cn)

	var certBytes []byte
	if issuer != nil {
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, issuer.Cert, &privKey.PublicKey, issuer.PrivateKey)
	} else {
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	}

	cert, _ := x509.ParseCertificate(certBytes)
	return ECCertTuple{
		Cert:       cert,
		PrivateKey: privKey,
	}
}

func getCertTemplate(isRoot bool, cn string) *x509.Certificate {
	template := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Notary"},
			Country:      []string{"US"},
			Province:     []string{"WA"},
			Locality:     []string{"Seattle"},
			CommonName:   cn,
		},
		NotBefore:   time.Now(),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if isRoot {
		template.SerialNumber = big.NewInt(1)
		template.NotAfter = time.Now().AddDate(0, 1, 0)
		template.KeyUsage = x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		template.MaxPathLen = 1
		template.IsCA = true
	} else {
		template.SerialNumber = big.NewInt(2)
		template.NotAfter = time.Now().AddDate(0, 0, 1)
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}

	return template
}
