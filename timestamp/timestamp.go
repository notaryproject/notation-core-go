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

// Package timestamp provides functionalities of timestamp countersignature
package timestamp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"time"

	nx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/notaryproject/tspclient-go"
)

// Timestamp generates a timestamp request and sends to TSA. It also validates
// the TSA certificate chain against Notary Project certificate and signature
// algorithm requirements.
// On success, it returns the full bytes of the timestamp token received from
// TSA.
//
// Reference: https://github.com/notaryproject/specifications/blob/v1.0.0/specs/signature-specification.md#leaf-certificates
func Timestamp(ctx context.Context, tsaURL string, signingTime *time.Time, opts tspclient.RequestOptions) ([]byte, error) {
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
	tsaCertChain, err := token.Verify(ctx, x509.VerifyOptions{})
	if err != nil {
		return nil, err
	}
	if err := nx509.ValidateTimeStampingCertChain(tsaCertChain, signingTime); err != nil {
		return nil, err
	}
	return resp.TimeStampToken.FullBytes, nil
}

// GenerateNonce generates a nonce for TSA request
func GenerateNonce() (*big.Int, error) {
	// Pick a random number from 0 to 2^159
	nonce, err := rand.Int(rand.Reader, (&big.Int{}).Lsh(big.NewInt(1), 159))
	if err != nil {
		return nil, errors.New("error generating nonce")
	}
	return nonce, nil
}
