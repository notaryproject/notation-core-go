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
	"context"
	"crypto"
	"errors"

	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/tspclient-go"
)

// Timestamp generates a timestamp request and sends to TSA. It also validates
// the TSA signing certificate against Notary Project certificate and signature
// algorithm requirements.
// On success, it returns the full bytes of the timestamp token received from
// TSA.
//
// Reference: https://github.com/notaryproject/specifications/blob/v1.0.0/specs/signature-specification.md#leaf-certificates
func Timestamp(ctx context.Context, tsaURL string, signature []byte, hash crypto.Hash) ([]byte, error) {
	opts := tspclient.RequestOptions{
		Content:       signature,
		HashAlgorithm: hash,
		CertReq:       true,
	}
	tsaRequest, err := tspclient.NewRequest(opts)
	if err != nil {
		return nil, err
	}
	httpTimeStamper, err := tspclient.NewHTTPTimestamper(nil, tsaURL)
	if err != nil {
		return nil, err
	}
	resp, err := httpTimeStamper.Timestamp(ctx, tsaRequest)
	if err != nil {
		return nil, err
	}
	token, err := resp.SignedToken()
	if err != nil {
		return nil, err
	}
	// there should be at least one valid TSA signing certificate in the
	// timestamp token
	for _, signerInfo := range token.SignerInfos {
		signingCertificate, err := token.GetSigningCertificate(&signerInfo)
		if err != nil || nx509.ValidateTimestampingSigningCeritifcate(signingCertificate) != nil {
			continue
		}
		return resp.TimeStampToken.FullBytes, nil
	}
	return nil, errors.New("no valid timestamp signing certificate was found in timestamp token")
}
