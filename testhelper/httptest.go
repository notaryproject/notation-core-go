// Package testhelper implements utility routines required for writing unit tests.
// The testhelper should only be used in unit tests.
package testhelper

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

type spyRoundTripper struct {
	backupTransport     http.RoundTripper
	certChain           []RSACertTuple
	desiredOCSPStatuses []ocsp.ResponseStatus
	revokedTime         *time.Time
	validPKIXNoCheck    bool
}

func (s spyRoundTripper) roundTripResponse(index int, expired bool) (*http.Response, error) {
	// Verify index of cert in chain
	if index == (len(s.certChain) - 1) {
		return nil, errors.New("OCSP cannot be performed on root")
	} else if index > (len(s.certChain) - 1) {
		return nil, errors.New("index exceeded chain size")
	}

	// Get desired status for index
	var status ocsp.ResponseStatus
	if index < len(s.desiredOCSPStatuses) {
		status = s.desiredOCSPStatuses[index]
	} else if len(s.desiredOCSPStatuses) == 0 {
		status = ocsp.Good
	} else {
		// Use last status from passed statuses
		status = s.desiredOCSPStatuses[len(s.desiredOCSPStatuses)-1]
	}

	// Create template for ocsp response
	var nextUpdate time.Time
	if expired {
		nextUpdate = time.Now().Add(-1 * time.Hour)
	} else {
		nextUpdate = time.Now().Add(time.Hour)
	}
	template := ocsp.Response{
		Status:       int(status),
		SerialNumber: s.certChain[index].Cert.SerialNumber,
		NextUpdate:   nextUpdate,
	}
	if status == ocsp.Revoked {
		if s.revokedTime != nil {
			template.RevokedAt = *s.revokedTime
		} else {
			template.RevokedAt = time.Now().Add(-1 * time.Hour)
		}
		template.RevocationReason = ocsp.Unspecified
	}
	if s.validPKIXNoCheck {
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Critical: false, Value: nil}}
	}

	// Create ocsp response
	response, err := ocsp.CreateResponse(s.certChain[index].Cert, s.certChain[index+1].Cert, template, s.certChain[index].PrivateKey)
	if err == nil {
		return &http.Response{
			Body:       io.NopCloser(bytes.NewBuffer(response)),
			StatusCode: http.StatusOK,
		}, nil
	} else {
		return nil, err
	}
}

func (s spyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if match, _ := regexp.MatchString("^\\/ocsp.*", req.URL.Path); match {
		return s.roundTripResponse(0, false)

	} else if match, _ := regexp.MatchString("^\\/expired_ocsp.*", req.URL.Path); match {
		return s.roundTripResponse(0, true)

	} else if match, _ := regexp.MatchString("^\\/chain_ocsp.*", req.URL.Path); match {
		// this url works with the revokable chain, which has url structure /chain_ocsp/<index> or /chain_ocsp/<index>/<base64_encoded_request>
		index, err := strconv.Atoi(strings.Split(req.URL.Path, "/")[2])
		if err != nil {
			return nil, err
		}
		return s.roundTripResponse(index, false)

	} else {
		fmt.Printf("%s did not match a specified path, using default transport", req.URL.Path)
		return s.backupTransport.RoundTrip(req)
	}
}

// Creates a mock HTTP Client (more accurately, a spy) that intercepts requests to /issuer and /ocsp endpoints
// The client's responses are dependent on the cert and desiredOCSPStatus
func MockClient(certChain []RSACertTuple, desiredOCSPStatuses []ocsp.ResponseStatus, revokedTime *time.Time, validPKIXNoCheck bool) *http.Client {
	return &http.Client{
		Transport: spyRoundTripper{
			backupTransport:     http.DefaultTransport,
			certChain:           certChain,
			desiredOCSPStatuses: desiredOCSPStatuses,
			revokedTime:         revokedTime,
			validPKIXNoCheck:    validPKIXNoCheck,
		},
	}
}
