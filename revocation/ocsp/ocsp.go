// Package OCSP provides methods for checking the OCSP revocation status of a
// certificate chain, as well as errors related to these checks
package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
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
	pkixNoCheckOID string = "1.3.6.1.5.5.7.48.1.5"
	// Max size determined from https://www.ibm.com/docs/en/sva/9.0.6?topic=stanza-ocsp-max-response-size.
	// Typical size is ~4 KB
	ocspMaxResponseSize int64 = 20480 //bytes
)

// CheckStatus checks OCSP based on the passed options and returns an array of
// result.CertRevocationResult objects that contains the results and error. The
// length of this array will always be equal to the length of the certificate
// chain.
func CheckStatus(opts Options) ([]*result.CertRevocationResult, error) {
	certResults := make([]*result.CertRevocationResult, len(opts.CertChain))

	if len(opts.CertChain) == 0 {
		return nil, result.InvalidChainError{Err: errors.New("chain does not contain any certificates")}
	}

	// Validate cert chain structure
	if err := coreX509.ValidateCodeSigningCertChain(opts.CertChain, &opts.SigningTime); err != nil {
		return nil, result.InvalidChainError{Err: err}
	}

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
			ServerResults: []*result.ServerResult{errToServerResult("", NoOCSPServerError{})},
		}
	}

	serverResults := make([]*result.ServerResult, len(ocspURLs))
	for serverIndex, server := range ocspURLs {
		serverResult := checkStatusFromServer(cert, issuer, server, opts)
		if serverResult.Result == result.ResultOK || serverResult.Result == result.ResultRevoked || errors.Is(serverResult.Error, UnknownStatusError{}) {
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
	if serverURL, err := url.Parse(server); err != nil || strings.ToLower(serverURL.Scheme) != "http" {
		// This function is only able to check servers that are accessible via HTTP
		return errToServerResult(server, OCSPCheckError{Err: fmt.Errorf("OCSPServer protocol %s is not supported", serverURL.Scheme)})
	}

	// Create OCSP Request
	resp, err := executeOCSPCheck(cert, issuer, server, opts)
	if err != nil {
		// If there is a server error, attempt all servers before determining what to return
		// to the user
		return errToServerResult(server, err)
	}

	// Validate OCSP response isn't expired
	if time.Now().After(resp.NextUpdate) {
		return errToServerResult(server, OCSPCheckError{Err: errors.New("expired OCSP response")})
	}

	// Check for presence of pkix-ocsp-no-check extension in response
	foundNoCheck := false
	for _, extension := range resp.Extensions {
		if !foundNoCheck && extension.Id.String() == pkixNoCheckOID {
			foundNoCheck = true
			break
		}
	}
	//lint:ignore SA9003 // Empty body in an if branch (Remove after adding CRL)
	if !foundNoCheck {
		// This will be ignored until CRL is implemented
		// If it isn't found, CRL should be used to verify the OCSP response
		// TODO: add CRL support
		// https://github.com/notaryproject/notation-core-go/issues/125
	}

	// No errors, valid server response
	switch resp.Status {
	case ocsp.Good:
		return errToServerResult(server, nil)
	case ocsp.Revoked:
		// Check if SigningTime was before the revocation
		if opts.SigningTime.Before(resp.RevokedAt) {
			return errToServerResult(server, nil)
		}
		return errToServerResult(server, RevokedError{})
	default:
		// ocsp.Unknown
		return errToServerResult(server, UnknownStatusError{})
	}
}

func executeOCSPCheck(cert, issuer *x509.Certificate, server string, opts Options) (*ocsp.Response, error) {
	// TODO: Look into other alternatives for specifying the Hash
	// https://github.com/notaryproject/notation-core-go/issues/139
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, OCSPCheckError{Err: err}
	}

	var resp *http.Response
	if base64.URLEncoding.EncodedLen(len(ocspRequest)) >= 255 {
		reader := bytes.NewReader(ocspRequest)
		resp, err = opts.HTTPClient.Post(server, "application/ocsp-request", reader)
	} else {
		encodedReq := base64.URLEncoding.EncodeToString(ocspRequest)
		var reqURL string
		reqURL, err = url.JoinPath(server, encodedReq)
		if err != nil {
			return nil, OCSPCheckError{Err: err}
		}
		resp, err = opts.HTTPClient.Get(reqURL)
	}

	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Timeout() {
			return nil, TimeoutError{}
		}
		return nil, OCSPCheckError{Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve OSCP: response had status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, ocspMaxResponseSize))
	if err != nil {
		return nil, OCSPCheckError{Err: err}
	}

	switch {
	case bytes.Equal(body, ocsp.UnauthorizedErrorResponse):
		return nil, OCSPCheckError{Err: errors.New("OSCP unauthorized")}
	case bytes.Equal(body, ocsp.MalformedRequestErrorResponse):
		return nil, OCSPCheckError{Err: errors.New("OSCP malformed")}
	case bytes.Equal(body, ocsp.InternalErrorErrorResponse):
		return nil, OCSPCheckError{Err: errors.New("OSCP internal error")}
	case bytes.Equal(body, ocsp.TryLaterErrorResponse):
		return nil, OCSPCheckError{Err: errors.New("OSCP try later")}
	case bytes.Equal(body, ocsp.SigRequredErrorResponse):
		return nil, OCSPCheckError{Err: errors.New("OSCP signature required")}
	}

	return ocsp.ParseResponseForCert(body, cert, issuer)
}

func errToServerResult(server string, err error) *result.ServerResult {
	if err == nil {
		return &result.ServerResult{
			Result: result.ResultOK,
			Server: server,
			Error:  nil,
		}
	} else if errors.Is(err, NoOCSPServerError{}) {
		return &result.ServerResult{
			Result: result.ResultNonRevokable,
			Server: server,
			Error:  nil,
		}
	} else if errors.Is(err, RevokedError{}) {
		return &result.ServerResult{
			Result: result.ResultRevoked,
			Server: server,
			Error:  err,
		}
	}
	// Includes OCSPCheckError, UnknownStatusError, result.InvalidChainError, and
	// TimeoutError
	return &result.ServerResult{
		Result: result.ResultUnknown,
		Server: server,
		Error:  err,
	}
}

func serverResultsToCertRevocationResult(serverResults []*result.ServerResult) *result.CertRevocationResult {
	if len(serverResults) == 0 {
		return nil
	}
	return &result.CertRevocationResult{
		Result:        serverResults[len(serverResults)-1].Result,
		ServerResults: serverResults,
	}
}
