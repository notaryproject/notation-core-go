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
// MessageImprint ::= SEQUENCE {
//  hashAlgorithm   AlgorithmIdentifier,
//  hashedMessage   OCTET STRING }
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// Request is a time-stamping request.
// TimeStampReq ::= SEQUENCE {
//  version         INTEGER                 { v1(1) },
//  messageImprint  MessageImprint,
//  reqPolicy       TSAPolicyID              OPTIONAL,
//  nonce           INTEGER                  OPTIONAL,
//  certReq         BOOLEAN                  DEFAULT FALSE,
//  extensions      [0] IMPLICIT Extensions  OPTIONAL }
type Request struct {
	Version        int // fixed to 1 as defined in RFC 3161 2.4.1 Request Format
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// NewRequest creates a request based on the given digest and hash algorithm.
func NewRequest(digest []byte, alg crypto.Hash) (*Request, error) {
	err := validate(digest, alg)
	if err != nil {
		return nil, err
	}

	hashAlg, err := getOID(alg)
	if err != nil {
		return nil, err
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

// NewRequestFromContent creates a request based on the given data and hash algorithm.
func NewRequestFromContent(content []byte, alg crypto.Hash) (*Request, error) {
	digest, err := hashutil.ComputeHash(alg, content)
	if err != nil {
		return nil, err
	}

	return NewRequest(digest, alg)
}

// MarshalBinary encodes the request to binary form.
// This method implements encoding.BinaryMarshaler
func (r *Request) MarshalBinary() ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil request")
	}
	return asn1.Marshal(*r)
}

// UnmarshalBinary decodes the request from binary form.
// This method implements encoding.BinaryUnmarshaler
func (r *Request) UnmarshalBinary(data []byte) error {
	_, err := asn1.Unmarshal(data, r)
	return err
}

// getOID returns corresponding ASN.1 OID for the given Hash algorithm.
func getOID(alg crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch alg {
	case crypto.SHA256:
		return oid.SHA256, nil
	case crypto.SHA384:
		return oid.SHA384, nil
	case crypto.SHA512:
		return oid.SHA512, nil
	}
	return nil, MalformedRequestError{msg: fmt.Sprintf("unsupported hashing algorithm: %s", alg)}
}

func validate(digest []byte, alg crypto.Hash) error {
	if !(alg == crypto.SHA256 || alg == crypto.SHA384 || alg == crypto.SHA512) {
		return MalformedRequestError{msg: fmt.Sprintf("unsupported hashing algorithm: %s", alg)}
	}

	if len(digest) != alg.Size() {
		return MalformedRequestError{msg: fmt.Sprintf("digest is of incorrect size: %d", len(digest))}
	}
	return nil
}