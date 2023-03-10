// Package testhelper implements utility routines required for writing unit tests.
// The testhelper should only be used in unit tests.
package testhelper

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/crl"
	"golang.org/x/crypto/ocsp"
)

type LogWriter struct{ *log.Logger }

func (w LogWriter) Write(b []byte) (int, error) {
	w.Printf("%s", b)
	return len(b), nil
}

func MockServer(cert *x509.Certificate, key *rsa.PrivateKey, desiredOCSPStatus ocsp.ResponseStatus, revokedInCRL bool, wg *sync.WaitGroup) *http.Server {
	template := ocsp.Response{
		Status:       int(desiredOCSPStatus),
		SerialNumber: cert.SerialNumber,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ocsp/", func(w http.ResponseWriter, r *http.Request) {
		response, err := ocsp.CreateResponse(cert, cert, template, key)
		if err == nil {
			w.Write(response)
		} else {
			fmt.Fprintf(w, "%v", err)
		}
	})

	mux.HandleFunc("/issuer", func(w http.ResponseWriter, r *http.Request) {
		w.Write(cert.Raw)
	})

	mux.HandleFunc("/crl", func(w http.ResponseWriter, r *http.Request) {
		var mockCRL []byte
		var err error
		if revokedInCRL {
			revokedCert := pkix.RevokedCertificate{SerialNumber: cert.SerialNumber, RevocationTime: time.Now().Add(-2 * time.Hour)}
			mockCRL, err = crl.CreateGenericCRL([]pkix.RevokedCertificate{revokedCert}, key, cert, time.Now()) //ensures it expires by next test
		} else {
			mockCRL, err = crl.CreateGenericCRL([]pkix.RevokedCertificate{}, key, cert, time.Now()) //ensures it expires by next test
		}
		if err == nil && mockCRL != nil {
			w.Write(mockCRL)
		} else {
			fmt.Fprintf(w, "%v", err)
		}
	})

	s := &http.Server{
		Addr:           ":8080",
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		defer wg.Done()

		if err := s.ListenAndServe(); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("error running http server: %v", err)
			}
		}
	}()
	return s
}
