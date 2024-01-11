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

package cms

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/internal/crypto/cms/encoding/ber"
	"github.com/notaryproject/notation-core-go/internal/crypto/hashutil"
	"github.com/notaryproject/notation-core-go/internal/crypto/oid"
)

// ParsedSignedData is a parsed SignedData structure for golang friendly types.
type ParsedSignedData struct {
	// Content is the content of the EncapsulatedContentInfo.
	Content []byte

	// ContentType is the content type of the EncapsulatedContentInfo.
	ContentType asn1.ObjectIdentifier

	// Certificates is the list of certificates in the SignedData.
	Certificates []*x509.Certificate

	// CRLs is the list of certificate revocation lists in the SignedData.
	CRLs []x509.RevocationList

	// SignerInfos is the list of signer information in the SignedData.
	SignerInfos []SignerInfo
}

// ParseSignedData parses ASN.1 BER-encoded SignedData structure to golang
// friendly types.
func ParseSignedData(berData []byte) (*ParsedSignedData, error) {
	data, err := ber.ConvertToDER(berData)
	if err != nil {
		return nil, SyntaxError{Message: "invalid signed data: failed to convert from BER to DER", Detail: err}
	}
	var contentInfo ContentInfo
	if _, err := asn1.Unmarshal(data, &contentInfo); err != nil {
		return nil, SyntaxError{Message: "invalid content info: failed to unmarshal DER to ContentInfo", Detail: err}
	}
	if !oid.SignedData.Equal(contentInfo.ContentType) {
		return nil, ErrNotSignedData
	}

	var signedData SignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, SyntaxError{Message: "invalid signed data", Detail: err}
	}
	certs, err := x509.ParseCertificates(signedData.Certificates.Bytes)
	if err != nil {
		return nil, SyntaxError{Message: "failed to parse X509 certificates from signed data", Detail: err}
	}

	return &ParsedSignedData{
		Content:      signedData.EncapsulatedContentInfo.Content,
		ContentType:  signedData.EncapsulatedContentInfo.ContentType,
		Certificates: certs,
		CRLs:         signedData.CRLs,
		SignerInfos:  signedData.SignerInfos,
	}, nil
}

// Verify attempts to verify the content in the parsed signed data against the signer
// information. The `Intermediates` in the verify options will be ignored and
// re-contrusted using the certificates in the parsed signed data.
// If more than one signature is present, the successful validation of any signature
// implies that the content in the parsed signed data is valid.
// On successful verification, the list of signing certificates that successfully
// verify is returned.
// If all signatures fail to verify, the last error is returned.
//
// References:
//   - RFC 5652 5   Signed-data Content Type
//   - RFC 5652 5.4 Message Digest Calculation Process
//   - RFC 5652 5.6 Signature Verification Process
//
// WARNING: this function doesn't do any revocation checking.
func (d *ParsedSignedData) Verify(opts x509.VerifyOptions) ([]*x509.Certificate, error) {
	if len(d.SignerInfos) == 0 {
		return nil, ErrSignerInfoNotFound
	}
	if len(d.Certificates) == 0 {
		return nil, ErrCertificateNotFound
	}

	intermediates := x509.NewCertPool()
	for _, cert := range d.Certificates {
		intermediates.AddCert(cert)
	}
	opts.Intermediates = intermediates
	verifiedSignerMap := map[string]*x509.Certificate{}
	var lastErr error
	for _, signerInfo := range d.SignerInfos {
		if signerInfo.Version != 1 {
			// Only IssuerAndSerialNumber is supported currently
			return nil, VerificationError{Message: fmt.Sprintf("invalid signer info version: only version 1 is supported; got %d", signerInfo.Version)}
		}

		signingCertificate := d.getCertificate(signerInfo.SignerIdentifier)
		if signingCertificate == nil {
			return nil, ErrCertificateNotFound
		}

		cert, err := d.verify(&signerInfo, signingCertificate, &opts)
		if err != nil {
			lastErr = err
			continue
		}
		thumbprint, err := hashutil.ComputeHash(crypto.SHA256, cert.Raw)
		if err != nil {
			return nil, err
		}
		verifiedSignerMap[hex.EncodeToString(thumbprint)] = cert
	}
	if len(verifiedSignerMap) == 0 {
		return nil, lastErr
	}

	verifiedSigningCertificates := make([]*x509.Certificate, 0, len(verifiedSignerMap))
	for _, cert := range verifiedSignerMap {
		verifiedSigningCertificates = append(verifiedSigningCertificates, cert)
	}
	return verifiedSigningCertificates, nil
}

// VerifySigner verifies the signerInfo against the signingCertificate.
//
// SignedData's certificates field is optional, so this function can be used
// to verify the signerInfo without the certificates field. Or the user doesn't
// trust the certificates of SignedData and the signer identifier of
// the SignerInfo (they are unsigned fields), this function can be used to
// verify the signerInfo against the user provided signingCertificate.
//
// References:
//   - RFC 5652 5   Signed-data Content Type
//   - RFC 5652 5.4 Message Digest Calculation Process
//   - RFC 5652 5.6 Signature Verification Process
//
// WARNING: this function doesn't do any revocation checking.
func (d *ParsedSignedData) VerifySigner(signerInfo *SignerInfo, signingCertificate *x509.Certificate, opts x509.VerifyOptions) (*x509.Certificate, error) {
	if signerInfo.Version != 1 {
		// Only IssuerAndSerialNumber is supported currently
		return nil, VerificationError{Message: fmt.Sprintf("invalid signer info version: only version 1 is supported; got %d", signerInfo.Version)}
	}

	intermediates := x509.NewCertPool()
	for _, cert := range d.Certificates {
		intermediates.AddCert(cert)
	}
	opts.Intermediates = intermediates

	if signingCertificate == nil {
		// user didn't provide signing certificate, find it from the signed data
		// certificates
		signingCertificate = d.getCertificate(signerInfo.SignerIdentifier)
		if signingCertificate == nil {
			return nil, ErrCertificateNotFound
		}
	} else {
		// user provided signing certificate must match the one in signer info
		if !bytes.Equal(signingCertificate.RawIssuer, signerInfo.SignerIdentifier.Issuer.FullBytes) || signingCertificate.SerialNumber.Cmp(signerInfo.SignerIdentifier.SerialNumber) != 0 {
			return nil, SyntaxError{Message: "signing certificate does not match signer info"}
		}
	}

	return d.verify(signerInfo, signingCertificate, &opts)
}

// verify verifies the trust in a top-down manner.
//
// References:
//   - RFC 5652 5.4 Message Digest Calculation Process
//   - RFC 5652 5.6 Signature Verification Process
func (d *ParsedSignedData) verify(signerInfo *SignerInfo, cert *x509.Certificate, opts *x509.VerifyOptions) (*x509.Certificate, error) {
	if cert == nil {
		return nil, ErrCertificateNotFound
	}
	// verify signer certificate
	certChains, err := cert.Verify(*opts)
	if err != nil {
		return cert, VerificationError{Detail: err}
	}

	// verify signature
	if err := d.verifySignature(signerInfo, cert); err != nil {
		return nil, err
	}

	// verify attribute
	return cert, d.verifyAttributes(signerInfo, certChains)
}

// verifySignature verifies the signature with a trusted certificate.
//
// References:
//   - RFC 5652 5.4 Message Digest Calculation Process
//   - RFC 5652 5.6 Signature Verification Process
func (d *ParsedSignedData) verifySignature(signerInfo *SignerInfo, cert *x509.Certificate) error {
	// verify signature
	algorithm := oid.ToSignatureAlgorithm(
		signerInfo.DigestAlgorithm.Algorithm,
		signerInfo.SignatureAlgorithm.Algorithm,
	)
	if algorithm == x509.UnknownSignatureAlgorithm {
		return VerificationError{Message: "unknown signature algorithm"}
	}

	signed := d.Content
	if len(signerInfo.SignedAttributes) > 0 {
		encoded, err := asn1.MarshalWithParams(signerInfo.SignedAttributes, "set")
		if err != nil {
			return VerificationError{Message: "invalid signed attributes", Detail: err}
		}
		signed = encoded
	}

	if err := cert.CheckSignature(algorithm, signed, signerInfo.Signature); err != nil {
		return VerificationError{Detail: err}
	}
	return nil
}

// verifyAttributes verifies the signed attributes.
//
// References:
//   - RFC 5652 5.3 SignerInfo Type
//   - RFC 5652 5.6 Signature Verification Process
func (d *ParsedSignedData) verifyAttributes(signerInfo *SignerInfo, chains [][]*x509.Certificate) error {
	// verify attributes if present
	if len(signerInfo.SignedAttributes) == 0 {
		if d.ContentType.Equal(oid.Data) {
			return nil
		}
		// signed attributes MUST be present if the content type of the
		// EncapsulatedContentInfo value being signed is not id-data.
		return VerificationError{Message: "missing signed attributes"}
	}

	var contentType asn1.ObjectIdentifier
	if err := signerInfo.SignedAttributes.TryGet(oid.ContentType, &contentType); err != nil {
		return VerificationError{Message: "invalid content type", Detail: err}
	}
	if !d.ContentType.Equal(contentType) {
		return VerificationError{Message: fmt.Sprintf("mismatch content type: found %q in signer info, and %q in signed data", contentType, d.ContentType)}
	}

	var expectedDigest []byte
	if err := signerInfo.SignedAttributes.TryGet(oid.MessageDigest, &expectedDigest); err != nil {
		return VerificationError{Message: "invalid message digest", Detail: err}
	}
	hash, ok := oid.ToHash(signerInfo.DigestAlgorithm.Algorithm)
	if !ok {
		return VerificationError{Message: "unsupported digest algorithm"}
	}
	actualDigest, err := hashutil.ComputeHash(hash, d.Content)
	if err != nil {
		return VerificationError{Message: "hash failure", Detail: err}
	}
	if !bytes.Equal(expectedDigest, actualDigest) {
		return VerificationError{Message: "mismatch message digest"}
	}

	// sanity check on signing time
	var signingTime time.Time
	if err := signerInfo.SignedAttributes.TryGet(oid.SigningTime, &signingTime); err != nil {
		if errors.Is(err, ErrAttributeNotFound) {
			return nil
		}
		return VerificationError{Message: "invalid signing time", Detail: err}
	}

	// verify signing time is within the validity period of all certificates
	// in the chain. As long as one chain is valid, the signature is valid.
	for _, chain := range chains {
		if isSigningTimeValid(chain, signingTime) {
			return nil
		}
	}

	return VerificationError{Message: "signature was generated outside certificate's validity period"}
}

// isSigningTimeValid helpes to check if signingTime is within the validity
// period of all certificates in the chain
func isSigningTimeValid(chain []*x509.Certificate, signingTime time.Time) bool {
	for _, cert := range chain {
		if signingTime.Before(cert.NotBefore) || signingTime.After(cert.NotAfter) {
			return false
		}
	}
	return true
}

// getCertificate finds the certificate by issuer name and issuer-specific
// serial number.
// Reference: RFC 5652 5 Signed-data Content Type
func (d *ParsedSignedData) getCertificate(ref IssuerAndSerialNumber) *x509.Certificate {
	for _, cert := range d.Certificates {
		if bytes.Equal(cert.RawIssuer, ref.Issuer.FullBytes) && cert.SerialNumber.Cmp(ref.SerialNumber) == 0 {
			return cert
		}
	}
	return nil
}
