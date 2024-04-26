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
	"encoding/asn1"
	"fmt"
	"math/big"
	mrand "math/rand"
	"strconv"
	"sync"
	"time"

	oid "github.com/notaryproject/notation-core-go/internal"
)

var (
	rsaRoot                  RSACertTuple
	rsaLeaf                  RSACertTuple
	revokableRSALeaf         RSACertTuple
	rsaLeafWithoutEKU        RSACertTuple
	ecdsaRoot                ECCertTuple
	ecdsaLeaf                ECCertTuple
	unsupportedECDSARoot     ECCertTuple
	unsupportedRSARoot       RSACertTuple
	rsaSelfSignedSigningCert RSACertTuple
)

var setupCertificatesOnce sync.Once

type RSACertTuple struct {
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

type ECCertTuple struct {
	Cert       *x509.Certificate
	PrivateKey *ecdsa.PrivateKey
}

// GetRSARootCertificate returns root certificate signed using RSA algorithm
func GetRSARootCertificate() RSACertTuple {
	setupCertificates()
	return rsaRoot
}

// GetRSALeafCertificate returns leaf certificate signed using RSA algorithm
func GetRSALeafCertificate() RSACertTuple {
	setupCertificates()
	return rsaLeaf
}

// GetRevokableRSALeafCertificate returns leaf certificate that specifies a local OCSP server signed using RSA algorithm
func GetRevokableRSALeafCertificate() RSACertTuple {
	setupCertificates()
	return revokableRSALeaf
}

// GetRevokableRSAChain returns a chain of certificates that specify a local OCSP server signed using RSA algorithm
func GetRevokableRSAChain(size int) []RSACertTuple {
	setupCertificates()
	chain := make([]RSACertTuple, size)
	chain[size-1] = getRevokableRSARootChainCertTuple("Notation Test Revokable RSA Chain Cert Root", size-1)
	for i := size - 2; i > 0; i-- {
		chain[i] = getRevokableRSAChainCertTuple(fmt.Sprintf("Notation Test Revokable RSA Chain Cert %d", size-i), &chain[i+1], i)
	}
	if size > 1 {
		chain[0] = getRevokableRSALeafChainCertTuple(fmt.Sprintf("Notation Test Revokable RSA Chain Cert %d", size), &chain[1], 0, true, false)
	}
	return chain
}

// GetRevokableRSATimestampChain returns a chain of certificates that specify a local OCSP server signed using RSA algorithm.
// The leaf certificate is a timestamp certificate.
func GetRevokableRSATimestampChain(size int) []RSACertTuple {
	setupCertificates()
	chain := make([]RSACertTuple, size)
	chain[size-1] = getRevokableRSARootChainCertTuple("Notation Test Revokable RSA Chain Cert Root", size-1)
	for i := size - 2; i > 0; i-- {
		chain[i] = getRevokableRSAChainCertTuple(fmt.Sprintf("Notation Test Revokable RSA Chain Cert %d", size-i), &chain[i+1], i)
	}
	if size > 1 {
		chain[0] = getRevokableRSALeafChainCertTuple(fmt.Sprintf("Notation Test Revokable RSA Chain Cert %d", size), &chain[1], 0, false, true)
	}
	return chain
}

// GetRSALeafCertificateWithoutEKU returns leaf certificate without EKU signed using RSA algorithm
func GetRSALeafCertificateWithoutEKU() RSACertTuple {
	setupCertificates()
	return rsaLeafWithoutEKU
}

// GetECRootCertificate returns root certificate signed using EC algorithm
func GetECRootCertificate() ECCertTuple {
	setupCertificates()
	return ecdsaRoot
}

// GetECLeafCertificate returns leaf certificate signed using EC algorithm
func GetECLeafCertificate() ECCertTuple {
	setupCertificates()
	return ecdsaLeaf
}

// GetUnsupportedRSACert returns certificate signed using RSA algorithm with key
// size of 1024 bits which is not supported by notary.
func GetUnsupportedRSACert() RSACertTuple {
	setupCertificates()
	return unsupportedRSARoot
}

// GetUnsupportedECCert returns certificate signed using EC algorithm with P-224
// curve which is not supported by notary.
func GetUnsupportedECCert() ECCertTuple {
	setupCertificates()
	return unsupportedECDSARoot
}

// GetRSASelfSignedSigningCertificate returns a self-signed certificate created which can be used for signing
func GetRSASelfSignedSigningCertificate() RSACertTuple {
	setupCertificates()
	return rsaSelfSignedSigningCert
}

func setupCertificates() {
	setupCertificatesOnce.Do(func() {
		rsaRoot = getRSACertTuple("Notation Test RSA Root", nil)
		rsaLeaf = getRSACertTuple("Notation Test RSA Leaf Cert", &rsaRoot)
		revokableRSALeaf = getRevokableRSACertTuple("Notation Test Revokable RSA Leaf Cert", &rsaRoot)
		rsaLeafWithoutEKU = getRSACertWithoutEKUTuple("Notation Test RSA Leaf without EKU Cert", &rsaRoot)
		ecdsaRoot = getECCertTuple("Notation Test EC Root", nil)
		ecdsaLeaf = getECCertTuple("Notation Test EC Leaf Cert", &ecdsaRoot)
		unsupportedECDSARoot = getECCertTupleWithCurve("Notation Test Invalid ECDSA Cert", nil, elliptic.P224())

		// This will be flagged by the static code analyzer as 'Use of a weak cryptographic key' but its intentional
		// and is used only for testing.
		k, _ := rsa.GenerateKey(rand.Reader, 1024)
		unsupportedRSARoot = GetRSACertTupleWithPK(k, "Notation Unsupported Root", nil)
		rsaSelfSignedSigningCert = GetRSASelfSignedSigningCertTuple("Notation Signing Test Root")
	})
}

func getRSACertTuple(cn string, issuer *RSACertTuple) RSACertTuple {
	pk, _ := rsa.GenerateKey(rand.Reader, 3072)
	return GetRSACertTupleWithPK(pk, cn, issuer)
}

func getRevokableRSACertTuple(cn string, issuer *RSACertTuple) RSACertTuple {
	template := getCertTemplate(issuer == nil, true, false, cn)
	template.OCSPServer = []string{"http://example.com/ocsp"}
	return getRSACertTupleWithTemplate(template, issuer.PrivateKey, issuer)
}

func getRevokableRSAChainCertTuple(cn string, previous *RSACertTuple, index int) RSACertTuple {
	template := getCertTemplate(previous == nil, true, false, cn)
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign
	template.OCSPServer = []string{fmt.Sprintf("http://example.com/chain_ocsp/%d", index)}
	return getRSACertTupleWithTemplate(template, previous.PrivateKey, previous)
}

func getRevokableRSARootChainCertTuple(cn string, pathLen int) RSACertTuple {
	pk, _ := rsa.GenerateKey(rand.Reader, 3072)
	template := getCertTemplate(true, true, false, cn)
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign
	template.MaxPathLen = pathLen
	return getRSACertTupleWithTemplate(template, pk, nil)
}

func getRevokableRSALeafChainCertTuple(cn string, issuer *RSACertTuple, index int, codesign, timestamp bool) RSACertTuple {
	template := getCertTemplate(false, codesign, timestamp, cn)
	template.BasicConstraintsValid = true
	template.IsCA = false
	template.KeyUsage = x509.KeyUsageDigitalSignature
	template.OCSPServer = []string{fmt.Sprintf("http://example.com/chain_ocsp/%d", index)}
	return getRSACertTupleWithTemplate(template, issuer.PrivateKey, issuer)
}

func getRSACertWithoutEKUTuple(cn string, issuer *RSACertTuple) RSACertTuple {
	pk, _ := rsa.GenerateKey(rand.Reader, 3072)
	template := getCertTemplate(issuer == nil, false, false, cn)
	return getRSACertTupleWithTemplate(template, pk, issuer)
}

func getECCertTupleWithCurve(cn string, issuer *ECCertTuple, curve elliptic.Curve) ECCertTuple {
	k, _ := ecdsa.GenerateKey(curve, rand.Reader)
	return GetECDSACertTupleWithPK(k, cn, issuer)
}

func getECCertTuple(cn string, issuer *ECCertTuple) ECCertTuple {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return GetECDSACertTupleWithPK(k, cn, issuer)
}

func GetRSASelfSignedSigningCertTuple(cn string) RSACertTuple {
	// Even though we are creating self-signed root, we are using false for 'isRoot' to not
	// add root CA's basic constraint, KU and EKU.
	template := getCertTemplate(false, true, false, cn)
	privKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	return getRSACertTupleWithTemplate(template, privKey, nil)
}

func GetRSACertTupleWithPK(privKey *rsa.PrivateKey, cn string, issuer *RSACertTuple) RSACertTuple {
	template := getCertTemplate(issuer == nil, true, false, cn)
	return getRSACertTupleWithTemplate(template, privKey, issuer)
}

func GetRSASelfSignedCertTupleWithPK(privKey *rsa.PrivateKey, cn string) RSACertTuple {
	template := getCertTemplate(false, true, false, cn)
	return getRSACertTupleWithTemplate(template, privKey, nil)
}

func getRSACertTupleWithTemplate(template *x509.Certificate, privKey *rsa.PrivateKey, issuer *RSACertTuple) RSACertTuple {
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
	template := getCertTemplate(issuer == nil, true, false, cn)

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

func getCertTemplate(isRoot bool, setCodeSignEKU, setTimestampEKU bool, cn string) *x509.Certificate {
	template := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Notary"},
			Country:      []string{"US"},
			Province:     []string{"WA"},
			Locality:     []string{"Seattle"},
			CommonName:   cn,
		},
		NotBefore: time.Now(),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	if setCodeSignEKU {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	} else if setTimestampEKU {
		ekuValue, _ := asn1.Marshal([]asn1.ObjectIdentifier{oid.TimeStamping})
		template.ExtraExtensions = []pkix.Extension{
			{
				Id:       oid.ExtKeyUsage,
				Critical: true,
				Value:    ekuValue,
			},
		}
	}

	if isRoot {
		template.SerialNumber = big.NewInt(1)
		template.NotAfter = time.Now().AddDate(0, 1, 0)
		template.KeyUsage = x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		template.MaxPathLen = 1
		template.IsCA = true
	} else {
		template.SerialNumber = big.NewInt(int64(mrand.Intn(200)))
		// TODO: for test purpose only, change it back when ready
		// template.NotAfter = time.Now().AddDate(0, 0, 1)
		template.NotAfter = time.Now().Add(10 * time.Minute)
	}
	return template
}

func GetRSACertTuple(size int) RSACertTuple {
	rsaRoot := GetRSARootCertificate()
	priv, _ := rsa.GenerateKey(rand.Reader, size)

	certTuple := GetRSACertTupleWithPK(
		priv,
		"Test RSA_"+strconv.Itoa(priv.Size()),
		&rsaRoot,
	)
	return certTuple
}

func GetECCertTuple(curve elliptic.Curve) ECCertTuple {
	ecdsaRoot := GetECRootCertificate()
	priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
	bitSize := priv.Params().BitSize

	certTuple := GetECDSACertTupleWithPK(
		priv,
		"Test EC_"+strconv.Itoa(bitSize),
		&ecdsaRoot,
	)
	return certTuple
}
