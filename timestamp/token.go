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

package timestamp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/notaryproject/notation-core-go/internal/crypto/cms"
	"github.com/notaryproject/notation-core-go/internal/crypto/hashutil"
	"github.com/notaryproject/notation-core-go/internal/crypto/oid"
)

// SignedToken is a parsed timestamp token with signatures.
type SignedToken cms.ParsedSignedData

// ParseSignedToken parses ASN.1 BER-encoded structure to SignedToken
// without verification.
// Callers should invoke Verify to verify the content before comsumption.
func ParseSignedToken(berData []byte) (*SignedToken, error) {
	signed, err := cms.ParseSignedData(berData)
	if err != nil {
		return nil, err
	}
	if !oid.TSTInfo.Equal(signed.ContentType) {
		return nil, fmt.Errorf("unexpected content type: %v", signed.ContentType)
	}
	return (*SignedToken)(signed), nil
}

// Verify verifies the signed token as CMS SignedData.
// An empty list of KeyUsages in VerifyOptions implies ExtKeyUsageTimeStamping.
func (t *SignedToken) Verify(opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	if len(opts.KeyUsages) == 0 {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}
	intermediates := x509.NewCertPool()
	for _, cert := range t.Certificates {
		intermediates.AddCert(cert)
	}
	opts.Intermediates = intermediates
	signed := (*cms.ParsedSignedData)(t)
	var verifiedCerts []*x509.Certificate
	var lastErr error
	for _, signerInfo := range t.SignerInfos {
		signingCertificate, err := t.GetSigningCertificate(&signerInfo)
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := signed.VerifySigner(&signerInfo, signingCertificate, opts); err != nil {
			lastErr = err
			continue
		}
		// RFC 3161 2.3: The corresponding certificate MUST contain only one instance of
		// the extended key usage field extension.
		if len(signingCertificate.ExtKeyUsage) == 1 && len(signingCertificate.UnknownExtKeyUsage) == 0 {
			verifiedCerts = append(verifiedCerts, signingCertificate)
		}
	}
	if len(verifiedCerts) == 0 {
		return nil, lastErr
	}
	return verifiedCerts, nil
}

// Info returns the timestamping information.
func (t *SignedToken) Info() (*TSTInfo, error) {
	var info TSTInfo
	if _, err := asn1.Unmarshal(t.Content, &info); err != nil {
		return nil, err
	}
	if info.Version != 1 {
		return nil, fmt.Errorf("TSTInfo must be 1, but got %d", info.Version)
	}
	return &info, nil
}

// GetSigningCertificate gets the signing certificate identified by CMS
// Signed-Data SignerInfo's SigningCertificate attribute. If the IssuerSerial
// field of signing certificate is missing, use signerInfo's sid instead.
// The identified signing certificate MUST match the hash in SigningCertificate.
//
// References: RFC 3161 2.4.1 & 2.4.2; RFC 5035 4
func (t *SignedToken) GetSigningCertificate(signerInfo *cms.SignerInfo) (*x509.Certificate, error) {
	var signingCertificateV2 SigningCertificateV2
	if err := signerInfo.SignedAttributes.TryGet(oid.SigningCertificateV2, &signingCertificateV2); err != nil {
		return nil, err
	}
	// get candidate signing certificate
	var candidateSigningCert *x509.Certificate
	signed := (*cms.ParsedSignedData)(t)
	if signingCertificateV2.Certificates[0].IssuerSerial.Issuer.FullBytes != nil {
		candidateSigningCert = signed.GetCertificate(signingCertificateV2.Certificates[0].IssuerSerial)
	} else {
		candidateSigningCert = signed.GetCertificate(signerInfo.SignerIdentifier)
	}
	if candidateSigningCert == nil {
		return nil, cms.ErrCertificateNotFound
	}
	// validate hash of candidate signing certificate
	hash := crypto.SHA256
	var ok bool
	if signingCertificateV2.Certificates[0].HashAlgorithm.Algorithm != nil {
		hash, ok = oid.ToHash(signingCertificateV2.Certificates[0].HashAlgorithm.Algorithm)
		if !ok {
			return nil, fmt.Errorf("unsupported certificate hash algorithm in SigningCertificate attribute")
		}
	}
	certHash, err := hashutil.ComputeHash(hash, candidateSigningCert.Raw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certHash, signingCertificateV2.Certificates[0].CertHash) {
		return nil, errors.New("candidate signing certificate's hash does not match certHash in SigningCertificate attribute")
	}
	return candidateSigningCert, nil
}

//	Accuracy ::= SEQUENCE {
//	 seconds     INTEGER             OPTIONAL,
//	 millis  [0] INTEGER (1..999)    OPTIONAL,
//	 micros  [1] INTEGER (1..999)    OPTIONAL }
type Accuracy struct {
	Seconds      int `asn1:"optional"`
	Milliseconds int `asn1:"optional,tag:0"`
	Microseconds int `asn1:"optional,tag:1"`
}

//	TSTInfo ::= SEQUENCE {
//	 version         INTEGER                 { v1(1) },
//	 policy          TSAPolicyId,
//	 messageImprint  MessageImprint,
//	 serialNumber    INTEGER,
//	 genTime         GeneralizedTime,
//	 accuracy        Accuracy                OPTIONAL,
//	 ordering        BOOLEAN                 DEFAULT FALSE,
//	 nonce           INTEGER                 OPTIONAL,
//	 tsa             [0] GeneralName         OPTIONAL,
//	 extensions      [1] IMPLICIT Extensions OPTIONAL }
type TSTInfo struct {
	Version        int // fixed to 1 as defined in RFC 3161 2.4.2 Response Format
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional,tag:0"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// VerifyContent verifies the message against the timestamp token information.
func (tst *TSTInfo) VerifyContent(message []byte) error {
	hashAlg := tst.MessageImprint.HashAlgorithm.Algorithm
	hash, ok := oid.ToHash(hashAlg)
	if !ok {
		return fmt.Errorf("unrecognized hash algorithm: %v", hashAlg)
	}
	messageDigest, err := hashutil.ComputeHash(hash, message)
	if err != nil {
		return err
	}

	return tst.Verify(messageDigest)
}

// Verify verifies the message digest against the timestamp token information.
func (tst *TSTInfo) Verify(messageDigest []byte) error {
	if !bytes.Equal(tst.MessageImprint.HashedMessage, messageDigest) {
		return errors.New("mismatch message digest")
	}
	return nil
}

// Timestamp returns the timestamp by TSA and its accuracy.
func (tst *TSTInfo) Timestamp() (time.Time, time.Duration) {
	accuracy := time.Duration(tst.Accuracy.Seconds)*time.Second +
		time.Duration(tst.Accuracy.Milliseconds)*time.Millisecond +
		time.Duration(tst.Accuracy.Microseconds)*time.Microsecond
	return tst.GenTime, accuracy
}
