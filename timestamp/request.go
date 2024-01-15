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
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/notaryproject/notation-core-go/internal/crypto/hashutil"
	"github.com/notaryproject/notation-core-go/internal/crypto/oid"
)

// MessageImprint contains the hash of the datum to be time-stamped.
//
//	MessageImprint ::= SEQUENCE {
//	 hashAlgorithm   AlgorithmIdentifier,
//	 hashedMessage   OCTET STRING }
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// Request is a time-stamping request.
//
//	TimeStampReq ::= SEQUENCE {
//	 version         INTEGER                 { v1(1) },
//	 messageImprint  MessageImprint,
//	 reqPolicy       TSAPolicyID              OPTIONAL,
//	 nonce           INTEGER                  OPTIONAL,
//	 certReq         BOOLEAN                  DEFAULT FALSE,
//	 extensions      [0] IMPLICIT Extensions  OPTIONAL }
type Request struct {
	Version        int // fixed to 1 as defined in RFC 3161 2.4.1 Request Format
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// NewRequest creates a request sent to TSA based on the given digest and
// hash algorithm.
//
// Parameters:
// digest - hashedMessage of timestamping request's messageImprint
// alg - hashing algorithm. Supported values are SHA256, SHA384, and SHA512
func NewRequest(digest []byte, alg crypto.Hash) (*Request, error) {
	hashAlg, err := oid.FromHash(alg)
	if err != nil {
		return nil, MalformedRequestError{msg: err.Error()}
	}
	if len(digest) != alg.Size() {
		return nil, MalformedRequestError{msg: fmt.Sprintf("digest is of incorrect size: %d", len(digest))}
	}
	return &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: hashAlg,
			},
			HashedMessage: digest,
		},
		CertReq: true,
	}, nil
}

// NewRequestFromContent creates a request based on the given data
// and hash algorithm.
func NewRequestFromContent(content []byte, alg crypto.Hash) (*Request, error) {
	digest, err := hashutil.ComputeHash(alg, content)
	if err != nil {
		return nil, err
	}

	return NewRequest(digest, alg)
}

// MarshalBinary encodes the request to binary form.
// This method implements encoding.BinaryMarshaler.
//
// Reference: https://pkg.go.dev/encoding#BinaryMarshaler
func (r *Request) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil request")
	}
	return asn1.Marshal(*r)
}

// UnmarshalBinary decodes the request from binary form.
// This method implements encoding.BinaryUnmarshaler.
//
// Reference: https://pkg.go.dev/encoding#BinaryUnmarshaler
func (r *Request) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}
