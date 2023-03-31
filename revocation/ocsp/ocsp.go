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

// OCSPStatus checks OCSP based on the passed options and returns a 2D array of
// errors. The size of these dimensions is as follows:
//   - 1st dimension will always be equal in length to the certificate chain.
//   - 2nd will have a length between 1 and the number of OCSPServers for the cert
//
// At each index, nil will be used to indicate no error. If there is an error,
// it will be one of the errors defined in errors.go.
//
// (e.g. for a chain with 3 certs (leaf, intermediate, root) with both the leaf
// and intermediate specifying 2 OCSP server, this could be a possible result):
//
//	[[PKIXNoCheckError, TimeoutError], [RevokedError], [nil]]
func OCSPStatus(opts Options) [][]error {
	certResults := make([][]error, len(opts.CertChain))

	if len(opts.CertChain) == 0 {
		return certResults
	}

	// Validate cert chain structure
	for i, cert := range opts.CertChain {
		if i != (len(opts.CertChain) - 1) {
			if err := validateIssuer(cert, opts.CertChain[i+1]); err != nil {
				fillResultsWithError(certResults, CheckOCSPError{Err: errors.New("invalid chain: expected chain to be correct and complete with each cert issued by the next in the chain")})
				return certResults
			}
		} else {
			if err := validateIssuer(cert, cert); err != nil {
				fillResultsWithError(certResults, CheckOCSPError{Err: errors.New("invalid chain: expected chain to end with root cert")})
				return certResults
			}
		}
	}

	// Check status for each cert in cert chain
	var wg sync.WaitGroup
	for i, cert := range opts.CertChain[:len(opts.CertChain)-1] {
		wg.Add(1)
		// Assume cert chain is accurate and next cert in chain is the issuer
		go func(i int, cert *x509.Certificate) {
			defer wg.Done()
			certResults[i] = certOCSPStatus(cert, opts.CertChain[i+1], opts)
		}(i, cert)
	}
	// Last is root cert, which will never be revoked by OCSP
	certResults[len(opts.CertChain)-1] = []error{nil}

	wg.Wait()
	return certResults
}

func fillResultsWithError(results [][]error, err error) {
	for i := range results {
		results[i] = []error{err}
	}
}

func validateIssuer(subject *x509.Certificate, issuer *x509.Certificate) error {
	if err := subject.CheckSignatureFrom(issuer); err != nil {
		return err
	}
	if !bytes.Equal(issuer.RawSubject, subject.RawIssuer) {
		return errors.New("parent's subject does not match issuer for a cert in the chain")
	}
	return nil
}

func certOCSPStatus(cert, issuer *x509.Certificate, opts Options) []error {
	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		// OCSP not enabled for this certificate.
		return []error{NoOCSPServerError{}}
	}

	serverErrs := make([]error, len(ocspURLs))
	for serverIndex, server := range ocspURLs {
		status, err := checkStatusFromServer(cert, issuer, server, opts)
		if err != nil {
			serverErrs[serverIndex] = err
			continue
		}

		// A valid response has been received from an OCSP server
		// Result should be based on only this response, not any errors from
		// other servers
		switch status {
		case ocsp.Revoked:
			return []error{RevokedError{}}
		case ocsp.Good:
			return []error{nil}
		default:
			return []error{UnknownStatusError{}}
		}

	}
	return serverErrs
}

func checkStatusFromServer(cert, issuer *x509.Certificate, server string, opts Options) (ocsp.ResponseStatus, error) {
	// Check valid server
	if !strings.HasPrefix(strings.ToLower(server), "http://") {
		// This function is only able to check servers that are accessible via HTTP
		return ocsp.Unknown, CheckOCSPError{Err: errors.New("OCSPServer must be accessible over HTTP")}
	}

	// Create OCSP Request
	resp, err := ocspRequest(cert, issuer, server, opts)
	if err != nil {
		// If there is a server error, attempt all servers before determining what to return
		// to the user
		if errors.Is(err, TimeoutError{}) {
			return ocsp.Unknown, err
		}
		return ocsp.Unknown, CheckOCSPError{Err: err}
	}

	// Validate OCSP response isn't expired
	if time.Now().After(resp.NextUpdate) {
		return ocsp.Unknown, CheckOCSPError{Err: errors.New("expired OCSP response")}
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
		return ocsp.Unknown, PKIXNoCheckError{}
	}

	// Check if SigningTime was before the revocation
	if opts.SigningTime.Before(resp.RevokedAt) {
		return ocsp.Good, nil
	}

	// No errors, valid server response
	return ocsp.ResponseStatus(resp.Status), nil
}

func ocspRequest(cert, issuer *x509.Certificate, server string, opts Options) (*ocsp.Response, error) {
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
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
			return nil, err
		}
		resp, err = opts.HTTPClient.Get(reqURL)
	}

	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Timeout() {
			return nil, TimeoutError{}
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve OSCP: response had status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, ocspMaxResponseSize))
	if err != nil {
		return nil, err
	}

	switch {
	case bytes.Equal(body, ocsp.UnauthorizedErrorResponse):
		return nil, errors.New("OSCP unauthorized")
	case bytes.Equal(body, ocsp.MalformedRequestErrorResponse):
		return nil, errors.New("OSCP malformed")
	case bytes.Equal(body, ocsp.InternalErrorErrorResponse):
		return nil, errors.New("OSCP internal error")
	case bytes.Equal(body, ocsp.TryLaterErrorResponse):
		return nil, errors.New("OSCP try later")
	case bytes.Equal(body, ocsp.SigRequredErrorResponse):
		return nil, errors.New("OSCP signature required")
	}

	return ocsp.ParseResponseForCert(body, cert, issuer)
}
