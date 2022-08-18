// Package testhelper implements utility routines required for writing unit tests.
// The testhelper should only be used in unit tests.
package testhelper

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

var (
	rsaRoot              RSACertTuple
	rsaLeaf              RSACertTuple
	ecdsaRoot            ECCertTuple
	ecdsaLeaf            ECCertTuple
	unsupportedEcdsaRoot ECCertTuple
	ed25519Leaf          ED25519CertTuple
	ed25519Root          ED25519CertTuple
	unsupported          RSACertTuple
)

type RSACertTuple struct {
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

type ECCertTuple struct {
	Cert       *x509.Certificate
	PrivateKey *ecdsa.PrivateKey
}

type ED25519CertTuple struct {
	Cert       *x509.Certificate
	PrivateKey *ed25519.PrivateKey
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

// GetED25519RootCertificate returns root certificate signed using ED25519 algorithm
func GetED25519RootCertificate() ED25519CertTuple {
	return ed25519Root
}

// GetED25519LeafCertificate returns leaf certificate signed using ED25519 algorithm
func GetED25519LeafCertificate() ED25519CertTuple {
	return ed25519Leaf
}

// GetUnsupportedCertificate returns certificate signed using RSA algorithm with key size of 1024 bits
// which is not supported by notary.
func GetUnsupportedCertificate() RSACertTuple {
	return unsupported
}

// GetUnsupportedRSACert returns certificate signed using RSA algorithm with key
// size of 1024 bits which is not supported by notary.
func GetUnsupportedRSACert() RSACertTuple {
	return unsupported
}

// GetUnsupportedECCert returns certificate signed using EC algorithm with P-224
// curve which is not supported by notary.
func GetUnsupportedECCert() ECCertTuple {
	return unsupportedEcdsaRoot
}

func setupCertificates() {
	rsaRoot = getCertTuple("Notation Test Root", nil)
	rsaLeaf = getCertTuple("Notation Test Leaf Cert", &rsaRoot)
	ecdsaRoot = getECCertTuple("Notation Test Root2", nil)
	ecdsaLeaf = getECCertTuple("Notation Test Leaf Cert", &ecdsaRoot)
	unsupportedEcdsaRoot = getECCertTupleWithCurve("Notation Test Invalid ECDSA Cert", nil, elliptic.P224())
	ed25519Root = getED25519CertTutple("Notation Test ED25519 root", nil)
	ed25519Leaf = getED25519CertTutple("Notation Test ED25519 leaf", &ed25519Root)

	// This will be flagged by the static code analyzer as 'Use of a weak cryptographic key' but its intentional
	// and is used only for testing.
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	unsupported = GetRSACertTupleWithPK(k, "Notation Unsupported Root", nil)
}

func getCertTuple(cn string, issuer *RSACertTuple) RSACertTuple {
	pk, _ := rsa.GenerateKey(rand.Reader, 3072)
	return GetRSACertTupleWithPK(pk, cn, issuer)
}

func getECCertTupleWithCurve(cn string, issuer *ECCertTuple, curve elliptic.Curve) ECCertTuple {
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	return GetECDSACertTupleWithPK(k, cn, issuer)
}

func getECCertTuple(cn string, issuer *ECCertTuple) ECCertTuple {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return GetECDSACertTupleWithPK(k, cn, issuer)
}

func getED25519CertTutple(cn string, issuer *ED25519CertTuple) ED25519CertTuple {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return GetED25519CertTupleWithPK(&priv, cn, issuer)
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

func GetED25519CertTupleWithPK(privKey *ed25519.PrivateKey, cn string, issuer *ED25519CertTuple) ED25519CertTuple {
	template := getCertTemplate(issuer == nil, cn)

	var certBytes []byte
	if issuer != nil {
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, issuer.Cert, privKey.Public(), issuer.PrivateKey)
	} else {
		certBytes, _ = x509.CreateCertificate(rand.Reader, template, template, privKey.Public(), privKey)
	}

	cert, _ := x509.ParseCertificate(certBytes)
	return ED25519CertTuple{
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
