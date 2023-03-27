package revocation

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Revocation is an internal struct used for revocation checking
type revocation struct {
	httpClient      *http.Client
	wg              sync.WaitGroup
	mergeErrorsFunc func(errors []error) error
}

// NewRevocation constructs a revocation object and substitutes default values for any that are passed as nil
func NewRevocation(httpClient *http.Client) *revocation {
	if httpClient != nil {
		return &revocation{httpClient: httpClient, wg: sync.WaitGroup{}, mergeErrorsFunc: defaultMergeErrors}
	}
	return &revocation{httpClient: http.DefaultClient, wg: sync.WaitGroup{}, mergeErrorsFunc: defaultMergeErrors}
}

// Validate checks OCSP, then CRL status, returns nil if all certs in the chain are not revoked.
// If there is an error, it will return one of the errors defined in this package in errors.go.
// (e.g. if a certificate in the chain is revoked by OCSP and there are no other errors, it will return revocation.RevokedInOCSPError)
//
// NOTE: Will only perform OCSP until CRL is implemented
func (r *revocation) Validate(certChain []*x509.Certificate) error {
	ocspErr := r.OCSPStatus(certChain)
	if ocspErr != nil {
		return ocspErr
	}
	return nil // This will eventually return the result of CRLStatus
}

// OCSPStatus checks OCSP, returns nil if all certs in the chain are not revoked.
// If there is an error, it will return one of the errors defined in this package in errors.go.
// (e.g. if a certificate in the chain is revoked by OCSP and there are no other errors, it will return revocation.RevokedInOCSPError)
func (r *revocation) OCSPStatus(certChain []*x509.Certificate) error {
	certResults := make([]error, len(certChain))
	for i, cert := range certChain {
		if i != (len(certChain) - 1) {
			if !isCorrectIssuer(cert, certChain[i+1]) {
				return CheckOCSPError{Err: errors.New("invalid chain: expected chain to be correct and complete with each cert issued by the next in the chain")}
			}
			r.wg.Add(1)
			// Assume cert chain is accurate and next cert in chain is the issuer
			go r.certOCSPStatus(cert, certChain[i+1], &certResults, i)
		} else {
			if !isCorrectIssuer(cert, cert) {
				return CheckOCSPError{Err: errors.New("invalid chain: expected chain to end with root cert")}
			}
			// Last is root cert, which will never be revoked by OCSP
			certResults[len(certChain)-1] = nil
		}
	}

	r.wg.Wait()
	return r.mergeErrorsFunc(certResults)
}

func isCorrectIssuer(subject *x509.Certificate, issuer *x509.Certificate) bool {
	if err := subject.CheckSignatureFrom(issuer); err != nil {
		return false
	}
	if !bytes.Equal(issuer.RawSubject, subject.RawIssuer) {
		return false
	}
	return true
}

func (r *revocation) certOCSPStatus(cert *x509.Certificate, issuer *x509.Certificate, results *[]error, resultIndex int) error {
	defer r.wg.Done()
	var err error

	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		// OCSP not enabled for this certificate.
		(*results)[resultIndex] = NoOCSPServerError{}
		return NoOCSPServerError{}
	}

	serverErrs := make([]error, len(ocspURLs))
	for serverIndex, server := range ocspURLs {
		resp, err := r.ocspRequest(cert, issuer, server)
		if err != nil {
			// If there is a server error, attempt all servers before determining what to return to the user
			serverErrs[serverIndex] = err
			continue
		}

		if time.Now().After(resp.NextUpdate) {
			err = errors.New("expired OCSP response")
			serverErrs[serverIndex] = err
			continue
		}

		foundNoCheck := false
		pkixNoCheckOID := "1.3.6.1.5.5.7.48.1.5"
		for _, extension := range resp.Extensions {
			if !foundNoCheck && extension.Id.String() == pkixNoCheckOID {
				foundNoCheck = true
			}
		}
		if !foundNoCheck {
			// This will be ignored until CRL is implemented
			// If it isn't found, CRL should be used to verify the OCSP response
			fmt.Printf("\n[WARNING] An ocsp signing cert is missing the id-pkix-ocsp-nocheck extension (%s)\n", pkixNoCheckOID)
		}

		if resp.Status == ocsp.Revoked {
			if time.Now().After(resp.RevokedAt) {
				(*results)[resultIndex] = RevokedInOCSPError{}
				return RevokedInOCSPError{}
			} else {
				(*results)[resultIndex] = nil
				return nil
			}
		} else if resp.Status == ocsp.Good {
			(*results)[resultIndex] = nil
			return nil
		} else {
			(*results)[resultIndex] = UnknownInOCSPError{}
			return UnknownInOCSPError{}
		}

	}
	// Errors in all server responses, determine the most pressing
	err = r.mergeErrorsFunc(serverErrs)
	(*results)[resultIndex] = err
	return err
}

func (r *revocation) ocspRequest(cert, issuer *x509.Certificate, server string) (*ocsp.Response, error) {
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, err
	}

	var resp *http.Response
	if len(ocspRequest) > 256 {
		buf := bytes.NewBuffer(ocspRequest)
		resp, err = r.httpClient.Post(server, "application/ocsp-request", buf)
	} else {
		reqURL := server + "/" + url.QueryEscape(base64.StdEncoding.EncodeToString(ocspRequest))
		resp, err = r.httpClient.Get(reqURL)
	}

	if err != nil {
		if urlErr, ok := err.(*url.Error); ok && urlErr.Timeout() {
			return nil, OCSPTimeoutError{}
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve OSCP: response had status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
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

// SetMergeErrorsFunction allows you to specify an alternative function to merge errors if the default does not fit your use case. You can also pass nil to reset it to the defaultMergeErrors function
func (r *revocation) SetMergeErrorsFunction(mergeErrorsFunc func(errors []error) error) {
	if mergeErrorsFunc == nil {
		r.mergeErrorsFunc = defaultMergeErrors
	} else {
		r.mergeErrorsFunc = mergeErrorsFunc
	}
}

// DefaultMergeErrors condenses errors for a list of errors (either for cert chain or OCSP servers) into one primary error
func defaultMergeErrors(errorList []error) error {
	var result error
	if len(errorList) > 0 {
		result = errorList[0]

		for _, err := range errorList {
			if err == nil {
				continue
			}
			switch t := err.(type) {
			case RevokedInOCSPError:
				// There is a revoked certificate
				// return since any cert being revoked means leaf is revoked
				return t
			case CheckOCSPError:
				// There is an error checking
				// return since any cert having error means chain has error (return earliest)
				return t
			case UnknownInOCSPError:
				// A cert in the chain has status unknown
				// will not return immediately (in case one is revoked or has error), but will override other chain errors
				result = t
			case NoOCSPServerError:
				// A cert in the chain does not have OCSP enabled
				// Still considered valid and not revoked
				// will not return immediately (in case there is higher level error)
				// will override OCSPTimeoutError and nil, but not UnknownInOCSPError (since a known unknown is worse than a cert without OCSP)
				if _, ok := result.(UnknownInOCSPError); !ok || result == nil {
					result = t
				}
			case OCSPTimeoutError:
				// A cert in the chain timed out while checking OCSP
				// will not return immediately (in case there is higher level error)
				// will override nil, but not UnknownInOCSPError or NoOCSPServerError (since timeout should only be conveyed if that is the only issue)
				if result == nil {
					result = t
				}
			default:
				return CheckOCSPError{Err: err}
			}
		}

		return result
	} else {
		return nil
	}
}
