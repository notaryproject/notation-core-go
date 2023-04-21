// Package ocsp provides methods for checking the OCSP revocation status of a
// certificate chain, as well as errors related to these checks
package ocsp

import (
	"bytes"
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
	"sync"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/result"
	coreX509 "github.com/notaryproject/notation-core-go/x509"
	"golang.org/x/crypto/ocsp"
)

// Options specifies values that are needed to check OCSP revocation
type Options struct {
	CertChain   []*x509.Certificate
	SigningTime time.Time
	HTTPClient  *http.Client
}

const (
	pkixNoCheckOID    string = "1.3.6.1.5.5.7.48.1.5"
	invalidityDateOID string = "2.5.29.24"
	// Max size determined from https://www.ibm.com/docs/en/sva/9.0.6?topic=stanza-ocsp-max-response-size.
	// Typical size is ~4 KB
	ocspMaxResponseSize int64 = 20480 //bytes
)

// CheckStatus checks OCSP based on the passed options and returns an array of
// result.CertRevocationResult objects that contains the results and error. The
// length of this array will always be equal to the length of the certificate
// chain.
func CheckStatus(opts Options) ([]*result.CertRevocationResult, error) {
	if len(opts.CertChain) == 0 {
		return nil, result.InvalidChainError{Err: errors.New("chain does not contain any certificates")}
	}

	// Validate cert chain structure
	// Since this is using authentic signing time, signing time may be zero.
	// Thus, it is better to pass nil here than fail for a cert's NotBefore
	// being after zero time
	if err := coreX509.ValidateCodeSigningCertChain(opts.CertChain, nil); err != nil {
		return nil, result.InvalidChainError{Err: err}
	}

	certResults := make([]*result.CertRevocationResult, len(opts.CertChain))

	// Check status for each cert in cert chain
	var wg sync.WaitGroup
	for i, cert := range opts.CertChain[:len(opts.CertChain)-1] {
		wg.Add(1)
		// Assume cert chain is accurate and next cert in chain is the issuer
		go func(i int, cert *x509.Certificate) {
			defer wg.Done()
			certResults[i] = certCheckStatus(cert, opts.CertChain[i+1], opts)
		}(i, cert)
	}
	// Last is root cert, which will never be revoked by OCSP
	certResults[len(opts.CertChain)-1] = &result.CertRevocationResult{
		Result: result.ResultNonRevokable,
		ServerResults: []*result.ServerResult{{
			Result: result.ResultNonRevokable,
			Error:  nil,
		}},
	}

	wg.Wait()
	return certResults, nil
}

func certCheckStatus(cert, issuer *x509.Certificate, opts Options) *result.CertRevocationResult {
	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		// OCSP not enabled for this certificate.
		return &result.CertRevocationResult{
			Result:        result.ResultNonRevokable,
			ServerResults: []*result.ServerResult{toServerResult("", NoServerError{})},
		}
	}

	serverResults := make([]*result.ServerResult, len(ocspURLs))
	for serverIndex, server := range ocspURLs {
		serverResult := checkStatusFromServer(cert, issuer, server, opts)
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

func checkStatusFromServer(cert, issuer *x509.Certificate, server string, opts Options) *result.ServerResult {
	// Check valid server
	if serverURL, err := url.Parse(server); err != nil || !strings.EqualFold(serverURL.Scheme, "http") {
		// This function is only able to check servers that are accessible via HTTP
		return toServerResult(server, GenericError{Err: fmt.Errorf("OCSPServer protocol %s is not supported", serverURL.Scheme)})
	}

	// Create OCSP Request
	resp, err := executeOCSPCheck(cert, issuer, server, opts)
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

func executeOCSPCheck(cert, issuer *x509.Certificate, server string, opts Options) (*ocsp.Response, error) {
	// TODO: Look into other alternatives for specifying the Hash
	// https://github.com/notaryproject/notation-core-go/issues/139
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, GenericError{Err: err}
	}

	var resp *http.Response
	if base64.URLEncoding.EncodedLen(len(ocspRequest)) >= 255 {
		reader := bytes.NewReader(ocspRequest)
		resp, err = opts.HTTPClient.Post(server, "application/ocsp-request", reader)
	} else {
		encodedReq := url.QueryEscape(base64.StdEncoding.EncodeToString(ocspRequest))
		var reqURL string
		reqURL, err = url.JoinPath(server, encodedReq)
		if err != nil {
			return nil, GenericError{Err: err}
		}
		resp, err = opts.HTTPClient.Get(reqURL)
	}

	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Timeout() {
			return nil, TimeoutError{}
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

func toServerResult(server string, err error) *result.ServerResult {
	switch t := err.(type) {
	case nil:
		return result.NewServerResult(result.ResultOK, server, nil)
	case NoServerError:
		return result.NewServerResult(result.ResultNonRevokable, server, nil)
	case RevokedError:
		return result.NewServerResult(result.ResultRevoked, server, t)
	default:
		// Includes GenericError, UnknownStatusError, result.InvalidChainError,
		// and TimeoutError
		return result.NewServerResult(result.ResultUnknown, server, t)
	}
}

func serverResultsToCertRevocationResult(serverResults []*result.ServerResult) *result.CertRevocationResult {
	return &result.CertRevocationResult{
		Result:        serverResults[len(serverResults)-1].Result,
		ServerResults: serverResults,
	}
}
