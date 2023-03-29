// Package OCSP provides methods for checking the OCSP revocation status of a certificate chain
// as well as errors related to these checks
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
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Logger is a simple logging interface based on what is logged in this package
type Logger interface {
	// Warnf logs a warn level message with format.
	Warnf(format string, args ...interface{})
	// Error logs an error level message.
	Error(args ...interface{})
}

// NoOpLogger is a No-Op implementation of Logger
type NoOpLogger struct{}

// Warnf for NoOpLogger does nothing
func (n *NoOpLogger) Warnf(format string, args ...interface{}) {}

// Error for NoOpLogger does nothing
func (n *NoOpLogger) Error(args ...interface{}) {}

type Options struct {
	CertChain       []*x509.Certificate
	SigningTime     time.Time
	HTTPClient      *http.Client
	MergeErrorsFunc func(errors []error) error
	Logger          Logger
}

const pkixNoCheckOID string = "1.3.6.1.5.5.7.48.1.5"
const ocspMaxResponseSize int64 = 20480 //bytes

func OCSPStatus(opts Options) error {
	wg := sync.WaitGroup{}
	certResults := make([]error, len(opts.CertChain))
	for i, cert := range opts.CertChain {
		if i != (len(opts.CertChain) - 1) {
			if err := validateIssuer(cert, opts.CertChain[i+1]); err != nil {
				return CheckOCSPError{Err: errors.New("invalid chain: expected chain to be correct and complete with each cert issued by the next in the chain")}
			}
			wg.Add(1)
			// Assume cert chain is accurate and next cert in chain is the issuer
			go certOCSPStatus(cert, opts.CertChain[i+1], &certResults[i], &wg, opts)
		} else {
			if err := validateIssuer(cert, cert); err != nil {
				return CheckOCSPError{Err: errors.New("invalid chain: expected chain to end with root cert")}
			}
			// Last is root cert, which will never be revoked by OCSP
			certResults[len(opts.CertChain)-1] = nil
		}
	}

	wg.Wait()
	for _, err := range certResults {
		if err != nil {
			opts.Logger.Error(err)
		}
	}
	return opts.MergeErrorsFunc(certResults)
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

func certOCSPStatus(cert *x509.Certificate, issuer *x509.Certificate, result *error, wg *sync.WaitGroup, opts Options) {
	defer wg.Done()
	var err error

	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		// OCSP not enabled for this certificate.
		(*result) = NoOCSPServerError{}
		return
	}

	serverErrs := make([]error, len(ocspURLs))
	for serverIndex, server := range ocspURLs {
		resp, err := ocspRequest(cert, issuer, server, opts)
		if err != nil {
			// If there is a server error, attempt all servers before determining what to return to the user
			opts.Logger.Error(err)
			serverErrs[serverIndex] = err
			continue
		}

		if opts.SigningTime.After(resp.NextUpdate) {
			err = errors.New("expired OCSP response")
			serverErrs[serverIndex] = err
			continue
		}

		foundNoCheck := false
		for _, extension := range resp.Extensions {
			if !foundNoCheck && extension.Id.String() == pkixNoCheckOID {
				foundNoCheck = true
			}
		}
		if !foundNoCheck {
			// This will be ignored until CRL is implemented
			// If it isn't found, CRL should be used to verify the OCSP response
			opts.Logger.Warnf("\nAn ocsp signing cert is missing the id-pkix-ocsp-nocheck extension (%s)\n", pkixNoCheckOID)
		}

		if resp.Status == ocsp.Revoked {
			if time.Now().After(resp.RevokedAt) {
				(*result) = RevokedError{}
				return
			} else {
				(*result) = nil
				return
			}
		} else if resp.Status == ocsp.Good {
			(*result) = nil
			return
		} else {
			(*result) = UnknownStatusError{}
			return
		}

	}
	err = opts.MergeErrorsFunc(serverErrs)
	(*result) = err
}

func ocspRequest(cert, issuer *x509.Certificate, server string, opts Options) (*ocsp.Response, error) {
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}

	var resp *http.Response
	if len(ocspRequest) > 256 {
		buf := bytes.NewBuffer(ocspRequest)
		resp, err = opts.HTTPClient.Post(server, "application/ocsp-request", buf)
	} else {
		reqURL := server + "/" + url.QueryEscape(base64.StdEncoding.EncodeToString(ocspRequest))
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
