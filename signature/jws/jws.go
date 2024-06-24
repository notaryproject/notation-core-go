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

package jws

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/timestamp"
	"github.com/notaryproject/tspclient-go"
)

func parseProtectedHeaders(encoded string) (*jwsProtectedHeader, error) {
	rawProtected, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}

	// To Unmarshal JSON with some known(jwsProtectedHeader), and some unknown(jwsProtectedHeader.ExtendedAttributes) field names.
	// We unmarshal twice: once into a value of type jwsProtectedHeader and once into a value of type jwsProtectedHeader.ExtendedAttributes(map[string]interface{})
	// and removing the keys are already been defined in jwsProtectedHeader.
	var protected jwsProtectedHeader
	if err = json.Unmarshal(rawProtected, &protected); err != nil {
		return nil, &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}
	if err = json.Unmarshal(rawProtected, &protected.ExtendedAttributes); err != nil {
		return nil, &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("jws envelope protected header can't be decoded: %s", err.Error())}
	}

	// delete attributes that are already defined in jwsProtectedHeader.
	for _, headerKey := range headerKeys {
		delete(protected.ExtendedAttributes, headerKey)
	}
	return &protected, nil
}

func populateProtectedHeaders(protectedHeader *jwsProtectedHeader, signerInfo *signature.SignerInfo) error {
	err := validateProtectedHeaders(protectedHeader)
	if err != nil {
		return err
	}

	if signerInfo.SignatureAlgorithm, err = getSignatureAlgorithm(protectedHeader.Algorithm); err != nil {
		return err
	}

	signerInfo.SignedAttributes.ExtendedAttributes = getExtendedAttributes(protectedHeader.ExtendedAttributes, protectedHeader.Critical)
	signerInfo.SignedAttributes.SigningScheme = protectedHeader.SigningScheme
	if protectedHeader.Expiry != nil {
		signerInfo.SignedAttributes.Expiry = *protectedHeader.Expiry
	}
	switch protectedHeader.SigningScheme {
	case signature.SigningSchemeX509:
		if protectedHeader.SigningTime != nil {
			signerInfo.SignedAttributes.SigningTime = *protectedHeader.SigningTime
		}
	case signature.SigningSchemeX509SigningAuthority:
		if protectedHeader.AuthenticSigningTime != nil {
			signerInfo.SignedAttributes.SigningTime = *protectedHeader.AuthenticSigningTime
		}
	default:
		return &signature.InvalidSignatureError{
			Msg: fmt.Sprintf("unsupported SigningScheme: `%v`", protectedHeader.SigningScheme),
		}
	}
	return nil
}

func validateProtectedHeaders(protectedHeader *jwsProtectedHeader) error {
	// validate headers that should not be present as per signing schemes
	switch protectedHeader.SigningScheme {
	case signature.SigningSchemeX509:
		if protectedHeader.AuthenticSigningTime != nil {
			return &signature.InvalidSignatureError{Msg: fmt.Sprintf("%q header must not be present for %s signing scheme", headerKeyAuthenticSigningTime, signature.SigningSchemeX509)}
		}
	case signature.SigningSchemeX509SigningAuthority:
		if protectedHeader.SigningTime != nil {
			return &signature.InvalidSignatureError{Msg: fmt.Sprintf("%q header must not be present for %s signing scheme", headerKeySigningTime, signature.SigningSchemeX509SigningAuthority)}
		}
		if protectedHeader.AuthenticSigningTime == nil {
			return &signature.InvalidSignatureError{Msg: fmt.Sprintf("%q header must be present for %s signing scheme", headerKeyAuthenticSigningTime, signature.SigningSchemeX509)}
		}
	default:
		return &signature.InvalidSignatureError{Msg: fmt.Sprintf("unsupported SigningScheme: `%v`", protectedHeader.SigningScheme)}
	}

	return validateCriticalHeaders(protectedHeader)
}

func validateCriticalHeaders(protectedHeader *jwsProtectedHeader) error {
	if len(protectedHeader.Critical) == 0 {
		return &signature.InvalidSignatureError{Msg: `missing "crit" header`}
	}

	mustMarkedCrit := map[string]bool{headerKeySigningScheme: true}
	if protectedHeader.Expiry != nil && !protectedHeader.Expiry.IsZero() {
		mustMarkedCrit[headerKeyExpiry] = true
	}

	if protectedHeader.SigningScheme == signature.SigningSchemeX509SigningAuthority {
		mustMarkedCrit[headerKeyAuthenticSigningTime] = true
	}

	for _, val := range protectedHeader.Critical {
		if _, ok := mustMarkedCrit[val]; ok {
			delete(mustMarkedCrit, val)
		} else {
			if _, ok := protectedHeader.ExtendedAttributes[val]; !ok {
				return &signature.InvalidSignatureError{
					Msg: fmt.Sprintf("%q header is marked critical but not present", val)}
			}
		}
	}

	// validate all required critical headers headers(as per spec) are marked as critical.
	if len(mustMarkedCrit) != 0 {
		// This is not taken care by VerifySignerInfo method
		keys := make([]string, 0, len(mustMarkedCrit))
		for k := range mustMarkedCrit {
			keys = append(keys, k)
		}
		return &signature.InvalidSignatureError{Msg: fmt.Sprintf("these required headers are not marked as critical: %v", keys)}
	}

	return nil
}

func getSignatureAlgorithm(alg string) (signature.Algorithm, error) {
	signatureAlg, ok := jwsAlgSignatureAlgMap[alg]
	if !ok {
		return 0, &signature.UnsupportedSignatureAlgoError{Alg: alg}
	}

	return signatureAlg, nil
}

func getExtendedAttributes(attrs map[string]interface{}, critical []string) []signature.Attribute {
	extendedAttr := make([]signature.Attribute, 0, len(attrs))
	for key, value := range attrs {
		extendedAttr = append(extendedAttr, signature.Attribute{
			Key:      key,
			Critical: contains(critical, key),
			Value:    value,
		})
	}
	return extendedAttr
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func generateJWS(compact string, req *signature.SignRequest, signingScheme string, certs []*x509.Certificate) (*jwsEnvelope, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		// this should never happen
		return nil, fmt.Errorf(
			"unexpected error occurred while generating a JWS-JSON serialization from compact serialization. want: len(parts) == 3, got: len(parts) == %d", len(parts))
	}
	protected := parts[0]
	payload := parts[1]
	sig := parts[2]

	rawCerts := make([][]byte, len(certs))
	for i, cert := range certs {
		rawCerts[i] = cert.Raw
	}

	jwsEnvelope := &jwsEnvelope{
		Protected: protected,
		Payload:   payload,
		Signature: sig,
		Header: jwsUnprotectedHeader{
			CertChain:    rawCerts,
			SigningAgent: req.SigningAgent,
		},
	}

	// timestamping
	if signingScheme == string(signature.SigningSchemeX509) && req.TSAServerURL != "" {
		primitiveSignature, err := base64.RawURLEncoding.DecodeString(sig)
		if err != nil {
			return nil, &signature.TimestampError{Detail: err}
		}
		ks, err := req.Signer.KeySpec()
		if err != nil {
			return nil, &signature.TimestampError{Detail: err}
		}
		hash := ks.SignatureAlgorithm().Hash()
		if hash == 0 {
			return nil, &signature.TimestampError{Msg: fmt.Sprintf("got hash value 0 from key spec %+v", ks)}
		}
		nonce, err := timestamp.GenerateNonce(rand.Reader)
		if err != nil {
			return nil, &signature.TimestampError{Detail: err}
		}
		timestampOpts := tspclient.RequestOptions{
			Content:                 primitiveSignature,
			HashAlgorithm:           hash,
			HashAlgorithmParameters: asn1.NullRawValue,
			Nonce:                   nonce,
		}
		timestampToken, err := timestamp.Timestamp(context.Background(), req.TSAServerURL, &req.SigningTime, req.TsaRootCertificate, timestampOpts)
		if err != nil {
			return nil, &signature.TimestampError{Detail: err}
		}
		// on success, embed the timestamp token to TimestampSignature
		jwsEnvelope.Header.TimestampSignature = timestampToken
	}
	return jwsEnvelope, nil
}

// getSignerAttributes merge extended signed attributes and protected header to be signed attributes.
func getSignedAttributes(req *signature.SignRequest, algorithm string) (map[string]interface{}, error) {
	extAttrs := make(map[string]interface{})
	crit := []string{headerKeySigningScheme}

	// write extended signed attributes to the extAttrs map
	for _, elm := range req.ExtendedSignedAttributes {
		key, ok := elm.Key.(string)
		if !ok {
			return nil, &signature.InvalidSignRequestError{Msg: "JWS envelope format only supports key of type string"}
		}
		if _, ok := extAttrs[key]; ok {
			return nil, &signature.InvalidSignRequestError{Msg: fmt.Sprintf("%q already exists in the extAttrs", key)}
		}
		extAttrs[key] = elm.Value
		if elm.Critical {
			crit = append(crit, key)
		}
	}

	jwsProtectedHeader := jwsProtectedHeader{
		Algorithm:     algorithm,
		ContentType:   req.Payload.ContentType,
		SigningScheme: req.SigningScheme,
	}

	switch req.SigningScheme {
	case signature.SigningSchemeX509:
		jwsProtectedHeader.SigningTime = &req.SigningTime
	case signature.SigningSchemeX509SigningAuthority:
		crit = append(crit, headerKeyAuthenticSigningTime)
		jwsProtectedHeader.AuthenticSigningTime = &req.SigningTime
	default:
		return nil, fmt.Errorf("unsupported SigningScheme: `%v`", req.SigningScheme)
	}

	if !req.Expiry.IsZero() {
		crit = append(crit, headerKeyExpiry)
		jwsProtectedHeader.Expiry = &req.Expiry
	}

	jwsProtectedHeader.Critical = crit
	m, err := convertToMap(jwsProtectedHeader)
	if err != nil {
		return nil, fmt.Errorf("unexpected error occurred while creating protected headers, Error: %s", err.Error())
	}

	return mergeMaps(m, extAttrs)
}

func convertToMap(i interface{}) (map[string]interface{}, error) {
	s, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	err = json.Unmarshal(s, &m)
	return m, err
}

func mergeMaps(maps ...map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			if _, ok := result[k]; ok {
				return nil, fmt.Errorf("attribute key:%s repeated", k)
			}
			result[k] = v
		}
	}
	return result, nil
}

// compactJWS converts Flattened JWS JSON Serialization Syntax (section-7.2.2) to
// JWS Compact Serialization (section-7.1)
//
// [RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515.html
func compactJWS(envelope *jwsEnvelope) string {
	return strings.Join([]string{
		envelope.Protected,
		envelope.Payload,
		envelope.Signature}, ".")
}
