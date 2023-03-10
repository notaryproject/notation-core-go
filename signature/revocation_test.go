package signature

import (
	"context"
	"sync"
	"testing"

	"github.com/notaryproject/notation-core-go/testhelper"
	"golang.org/x/crypto/ocsp"
)

func TestCheckRevocationStatus(t *testing.T) {
	revokableCertTuple := testhelper.GetRevokableRSALeafCertificate()
	revokableCert := revokableCertTuple.Cert
	revokableKey := revokableCertTuple.PrivateKey

	rc := NewRevocationChecker()

	t.Run("check non-revoked cert", func(t *testing.T) {
		serverShutdownWaitGroup := &sync.WaitGroup{}
		serverShutdownWaitGroup.Add(1)
		srv := testhelper.MockServer(revokableCert, revokableKey, ocsp.Good, false, serverShutdownWaitGroup)

		revoked, err := rc.CheckRevocationStatus(revokableCert)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
		if revoked {
			t.Errorf("Expected certificate to not be revoked")
		}
		if err := srv.Shutdown(context.TODO()); err != nil {
			t.Errorf("Error while shutting down server: %v", err)
		}
		serverShutdownWaitGroup.Wait()
	})
	t.Run("check cert with Unknown OCSP response", func(t *testing.T) {
		serverShutdownWaitGroup := &sync.WaitGroup{}
		serverShutdownWaitGroup.Add(1)
		srv := testhelper.MockServer(revokableCert, revokableKey, ocsp.Unknown, false, serverShutdownWaitGroup)

		revoked, err := rc.CheckRevocationStatus(revokableCert)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
		if !revoked {
			t.Errorf("Expected certificate to be revoked")
		}
		if err := srv.Shutdown(context.TODO()); err != nil {
			t.Errorf("Error while shutting down server: %v", err)
		}
		serverShutdownWaitGroup.Wait()
	})
	t.Run("check OCSP revoked cert", func(t *testing.T) {
		serverShutdownWaitGroup := &sync.WaitGroup{}
		serverShutdownWaitGroup.Add(1)
		srv := testhelper.MockServer(revokableCert, revokableKey, ocsp.Revoked, false, serverShutdownWaitGroup)

		revoked, err := rc.CheckRevocationStatus(revokableCert)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
		if !revoked {
			t.Errorf("Expected certificate to be revoked")
		}
		if err := srv.Shutdown(context.TODO()); err != nil {
			t.Errorf("Error while shutting down server: %v", err)
		}
		serverShutdownWaitGroup.Wait()
	})
	t.Run("check CRL revoked cert", func(t *testing.T) {
		serverShutdownWaitGroup := &sync.WaitGroup{}
		serverShutdownWaitGroup.Add(1)
		srv := testhelper.MockServer(revokableCert, revokableKey, ocsp.Good, true, serverShutdownWaitGroup)

		revoked, err := rc.CheckRevocationStatus(revokableCert)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
		if !revoked {
			t.Errorf("Expected certificate to be revoked")
		}
		if err := srv.Shutdown(context.TODO()); err != nil {
			t.Errorf("Error while shutting down server: %v", err)
		}
		serverShutdownWaitGroup.Wait()
	})
	t.Run("check OCSP and CRL revoked cert", func(t *testing.T) {
		serverShutdownWaitGroup := &sync.WaitGroup{}
		serverShutdownWaitGroup.Add(1)
		srv := testhelper.MockServer(revokableCert, revokableKey, ocsp.Revoked, true, serverShutdownWaitGroup)

		revoked, err := rc.CheckRevocationStatus(revokableCert)
		if err != nil {
			t.Errorf("Unexpected error while checking revocation status: %v", err)
		}
		if !revoked {
			t.Errorf("Expected certificate to be revoked")
		}
		if err := srv.Shutdown(context.TODO()); err != nil {
			t.Errorf("Error while shutting down server: %v", err)
		}
		serverShutdownWaitGroup.Wait()
	})
}
