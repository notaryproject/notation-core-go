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

	"github.com/notaryproject/notation-core-go/revocation/base"
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
	pkixNoCheckOID      string = "1.3.6.1.5.5.7.48.1.5"
	ocspMaxResponseSize int64  = 20480 //bytes
)

// CheckStatus checks OCSP based on the passed options and returns an array of
// base.CertRevocationResult objects that contains the results and error. The
// length of this array will always be equal to the length of the certificate
// chain.
func CheckStatus(opts Options) ([]*base.CertRevocationResult, error) {
	result := make([]*base.CertRevocationResult, len(opts.CertChain))

	if len(opts.CertChain) == 0 {
		return result, nil
	}

	// Validate cert chain structure
	if err := coreX509.ValidateCodeSigningCertChain(opts.CertChain, &opts.SigningTime); err != nil {
		return nil, base.InvalidChainError{Err: err}
	}

	// Check status for each cert in cert chain
	var wg sync.WaitGroup
	for i, cert := range opts.CertChain[:len(opts.CertChain)-1] {
		wg.Add(1)
		// Assume cert chain is accurate and next cert in chain is the issuer
		go func(i int, cert *x509.Certificate) {
			defer wg.Done()
			result[i] = certCheckStatus(cert, opts.CertChain[i+1], opts)
		}(i, cert)
	}
	// Last is root cert, which will never be revoked by OCSP
	result[len(opts.CertChain)-1] = &base.CertRevocationResult{
		Result: base.ResultNonRevokable,
		ServerResults: []*base.ServerResult{{
			Result: base.ResultNonRevokable,
			Error:  nil,
		}},
	}

	wg.Wait()
	return result, nil
}

func certCheckStatus(cert, issuer *x509.Certificate, opts Options) *base.CertRevocationResult {
	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		// OCSP not enabled for this certificate.
		return &base.CertRevocationResult{
			Result:        base.ResultNonRevokable,
			ServerResults: []*base.ServerResult{errToServerResult(NoOCSPServerError{})},
		}
	}

	serverResults := make([]*base.ServerResult, len(ocspURLs))
	for serverIndex, server := range ocspURLs {
		serverResult := checkStatusFromServer(cert, issuer, server, opts)
		if serverResult.Result == base.ResultOK || serverResult.Result == base.ResultRevoked || errors.Is(serverResult.Error, UnknownStatusError{}) {
			// A valid response has been received from an OCSP server
			// Result should be based on only this response, not any errors from
			// other servers
			return serverResultsToCertRevocationResult([]*base.ServerResult{serverResult})
		}
		serverResults[serverIndex] = serverResult
	}
	return serverResultsToCertRevocationResult(serverResults)
}

func checkStatusFromServer(cert, issuer *x509.Certificate, server string, opts Options) *base.ServerResult {
	// Check valid server
	if serverURL, err := url.Parse(server); err != nil || strings.ToLower(serverURL.Scheme) != "http" {
		// This function is only able to check servers that are accessible via HTTP
		return errToServerResult(OCSPCheckError{Err: fmt.Errorf("OCSPServer protocol %s is not supported", serverURL.Scheme)})
	}

	// Create OCSP Request
	resp, err := executeOCSPCheck(cert, issuer, server, opts)
	if err != nil {
		// If there is a server error, attempt all servers before determining what to return
		// to the user
		return errToServerResult(err)
	}

	// Validate OCSP response isn't expired
	if time.Now().After(resp.NextUpdate) {
		return errToServerResult(OCSPCheckError{Err: errors.New("expired OCSP response")})
	}

	// Check for presence of pkix-ocsp-no-check extension in response
	foundNoCheck := false
	for _, extension := range resp.Extensions {
		if !foundNoCheck && extension.Id.String() == pkixNoCheckOID {
			foundNoCheck = true
			break
		}
	}
	if !foundNoCheck {
		// This will be ignored until CRL is implemented
		// If it isn't found, CRL should be used to verify the OCSP response
		// TODO: add CRL support
		// https://github.com/notaryproject/notation-core-go/issues/125
		return errToServerResult(PKIXNoCheckError{})
	}

	// No errors, valid server response
	switch resp.Status {
	case ocsp.Good:
		return errToServerResult(nil)
	case ocsp.Revoked:
		// Check if SigningTime was before the revocation
		if opts.SigningTime.Before(resp.RevokedAt) {
			return errToServerResult(nil)
		}
		return errToServerResult(RevokedError{})
	default:
		// ocsp.Unknown
		return errToServerResult(UnknownStatusError{})
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

func errToServerResult(err error) *base.ServerResult {
	if err == nil {
		return &base.ServerResult{
			Result: base.ResultOK,
			Error:  nil,
		}
	} else if errors.Is(err, NoOCSPServerError{}) || errors.Is(err, PKIXNoCheckError{}) {
		return &base.ServerResult{
			Result: base.ResultNonRevokable,
			Error:  nil,
		}
	} else if errors.Is(err, RevokedError{}) {
		return &base.ServerResult{
			Result: base.ResultRevoked,
			Error:  err,
		}
	}
	// Includes OCSPCheckError, UnknownStatusError, base.InvalidChainError, and
	// TimeoutError
	return &base.ServerResult{
		Result: base.ResultUnknown,
		Error:  err,
	}
}

func serverResultsToCertRevocationResult(serverResults []*base.ServerResult) *base.CertRevocationResult {
	currResult := base.ResultOK
	for _, serverResult := range serverResults {
		switch serverResult.Result {
		case base.ResultRevoked:
			currResult = base.ResultRevoked
		case base.ResultUnknown:
			if currResult != base.ResultRevoked {
				currResult = base.ResultUnknown
			}
		case base.ResultNonRevokable:
			if currResult != base.ResultRevoked && currResult != base.ResultUnknown {
				currResult = base.ResultNonRevokable
			}
		}
	}
	return &base.CertRevocationResult{
		Result:        currResult,
		ServerResults: serverResults,
	}
}
