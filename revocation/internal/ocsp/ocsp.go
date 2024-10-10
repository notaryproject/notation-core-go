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

// Package ocsp provides methods for checking the OCSP revocation status of a
// certificate chain, as well as errors related to these checks
package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
	"golang.org/x/crypto/ocsp"
)

// CertCheckStatusOptions specifies values that are needed to check OCSP revocation
type CertCheckStatusOptions struct {
	// HTTPClient is the HTTP client used to perform the OCSP request
	HTTPClient *http.Client

	// SigningTime is used to compare with the invalidity date during revocation
	SigningTime time.Time
}

const (
	pkixNoCheckOID    string = "1.3.6.1.5.5.7.48.1.5"
	invalidityDateOID string = "2.5.29.24"
	// Max size determined from https://www.ibm.com/docs/en/sva/9.0.6?topic=stanza-ocsp-max-response-size.
	// Typical size is ~4 KB
	ocspMaxResponseSize int64 = 20480 //bytes
)

// CertCheckStatus checks the revocation status of a certificate using OCSP
func CertCheckStatus(ctx context.Context, cert, issuer *x509.Certificate, opts CertCheckStatusOptions) *result.CertRevocationResult {
	if !Supported(cert) {
		// OCSP not enabled for this certificate.
		return &result.CertRevocationResult{
			Result:           result.ResultNonRevokable,
			ServerResults:    []*result.ServerResult{toServerResult("", NoServerError{})},
			RevocationMethod: result.RevocationMethodOCSP,
		}
	}
	ocspURLs := cert.OCSPServer

	serverResults := make([]*result.ServerResult, len(ocspURLs))
	for serverIndex, server := range ocspURLs {
		serverResult := checkStatusFromServer(ctx, cert, issuer, server, opts)
		if serverResult.Result == result.ResultOK ||
			serverResult.Result == result.ResultRevoked ||
			(serverResult.Result == result.ResultUnknown && errors.Is(serverResult.Error, UnknownStatusError{})) {
			// A valid response has been received from an OCSP server
			// Result should be based on only this response, not any errors from
			// other servers
			return serverResultsToCertRevocationResult([]*result.ServerResult{serverResult})
		}
		serverResults[serverIndex] = serverResult
	}
	return serverResultsToCertRevocationResult(serverResults)
}

// Supported returns true if the certificate supports OCSP.
func Supported(cert *x509.Certificate) bool {
	return cert != nil && len(cert.OCSPServer) > 0
}

func checkStatusFromServer(ctx context.Context, cert, issuer *x509.Certificate, server string, opts CertCheckStatusOptions) *result.ServerResult {
	// Check valid server
	if serverURL, err := url.Parse(server); err != nil || !strings.EqualFold(serverURL.Scheme, "http") {
		// This function is only able to check servers that are accessible via HTTP
		return toServerResult(server, GenericError{Err: fmt.Errorf("OCSPServer protocol %s is not supported", serverURL.Scheme)})
	}

	// Create OCSP Request
	resp, err := executeOCSPCheck(ctx, cert, issuer, server, opts)
	if err != nil {
		// If there is a server error, attempt all servers before determining what to return
		// to the user
		return toServerResult(server, err)
	}

	// Validate OCSP response isn't expired
	if time.Now().After(resp.NextUpdate) {
		return toServerResult(server, GenericError{Err: errors.New("expired OCSP response")})
	}

	// Handle pkix-ocsp-no-check and id-ce-invalidityDate extensions if present
	// in response
	extensionMap := extensionsToMap(resp.Extensions)
	if _, foundNoCheck := extensionMap[pkixNoCheckOID]; !foundNoCheck {
		// This will be ignored until CRL is implemented
		// If it isn't found, CRL should be used to verify the OCSP response
		_ = foundNoCheck // needed to bypass linter warnings (Remove after adding CRL)
		// TODO: add CRL support
		// https://github.com/notaryproject/notation-core-go/issues/125
	}
	if invalidityDateBytes, foundInvalidityDate := extensionMap[invalidityDateOID]; foundInvalidityDate && !opts.SigningTime.IsZero() && resp.Status == ocsp.Revoked {
		var invalidityDate time.Time
		rest, err := asn1.UnmarshalWithParams(invalidityDateBytes, &invalidityDate, "generalized")
		if len(rest) == 0 && err == nil && opts.SigningTime.Before(invalidityDate) {
			return toServerResult(server, nil)
		}
	}

	// No errors, valid server response
	switch resp.Status {
	case ocsp.Good:
		return toServerResult(server, nil)
	case ocsp.Revoked:
		return toServerResult(server, RevokedError{})
	default:
		// ocsp.Unknown
		return toServerResult(server, UnknownStatusError{})
	}
}

func extensionsToMap(extensions []pkix.Extension) map[string][]byte {
	extensionMap := make(map[string][]byte)
	for _, extension := range extensions {
		extensionMap[extension.Id.String()] = extension.Value
	}
	return extensionMap
}

func executeOCSPCheck(ctx context.Context, cert, issuer *x509.Certificate, server string, opts CertCheckStatusOptions) (*ocsp.Response, error) {
	// TODO: Look into other alternatives for specifying the Hash
	// https://github.com/notaryproject/notation-core-go/issues/139
	// The following do not support SHA256 hashes:
	//  - Microsoft
	//  - Entrust
	//  - Let's Encrypt
	//  - Digicert (sometimes)
	// As this represents a large percentage of public CAs, we are using the
	// hashing algorithm SHA1, which has been confirmed to be supported by all
	// that were tested.
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, GenericError{Err: err}
	}

	var resp *http.Response
	postRequired := base64.StdEncoding.EncodedLen(len(ocspRequest)) >= 255
	if !postRequired {
		encodedReq := url.QueryEscape(base64.StdEncoding.EncodeToString(ocspRequest))
		if len(encodedReq) < 255 {
			var reqURL string
			reqURL, err = url.JoinPath(server, encodedReq)
			if err != nil {
				return nil, GenericError{Err: err}
			}
			var httpReq *http.Request
			httpReq, err = http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
			if err != nil {
				return nil, err
			}
			resp, err = opts.HTTPClient.Do(httpReq)
		} else {
			resp, err = postRequest(ctx, ocspRequest, server, opts.HTTPClient)
		}
	} else {
		resp, err = postRequest(ctx, ocspRequest, server, opts.HTTPClient)
	}

	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Timeout() {
			return nil, TimeoutError{
				timeout: opts.HTTPClient.Timeout,
			}
		}
		return nil, GenericError{Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve OCSP: response had status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, ocspMaxResponseSize))
	if err != nil {
		return nil, GenericError{Err: err}
	}

	switch {
	case bytes.Equal(body, ocsp.UnauthorizedErrorResponse):
		return nil, GenericError{Err: errors.New("OCSP unauthorized")}
	case bytes.Equal(body, ocsp.MalformedRequestErrorResponse):
		return nil, GenericError{Err: errors.New("OCSP malformed")}
	case bytes.Equal(body, ocsp.InternalErrorErrorResponse):
		return nil, GenericError{Err: errors.New("OCSP internal error")}
	case bytes.Equal(body, ocsp.TryLaterErrorResponse):
		return nil, GenericError{Err: errors.New("OCSP try later")}
	case bytes.Equal(body, ocsp.SigRequredErrorResponse):
		return nil, GenericError{Err: errors.New("OCSP signature required")}
	}

	return ocsp.ParseResponseForCert(body, cert, issuer)
}

func postRequest(ctx context.Context, req []byte, server string, httpClient *http.Client) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	return httpClient.Do(httpReq)
}

func toServerResult(server string, err error) *result.ServerResult {
	var serverResult *result.ServerResult
	switch t := err.(type) {
	case nil:
		serverResult = result.NewServerResult(result.ResultOK, server, nil)
	case NoServerError:
		serverResult = result.NewServerResult(result.ResultNonRevokable, server, nil)
	case RevokedError:
		serverResult = result.NewServerResult(result.ResultRevoked, server, t)
	default:
		// Includes GenericError, UnknownStatusError, result.InvalidChainError,
		// and TimeoutError
		serverResult = result.NewServerResult(result.ResultUnknown, server, t)
	}
	serverResult.RevocationMethod = result.RevocationMethodOCSP
	return serverResult
}

func serverResultsToCertRevocationResult(serverResults []*result.ServerResult) *result.CertRevocationResult {
	return &result.CertRevocationResult{
		Result:           serverResults[len(serverResults)-1].Result,
		ServerResults:    serverResults,
		RevocationMethod: result.RevocationMethodOCSP,
	}
}
