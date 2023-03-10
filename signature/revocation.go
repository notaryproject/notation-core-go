package signature

import (
	"crypto/x509"
	"net/http"

	"github.com/cloudflare/cfssl/revoke"
)

type RevocationChecker struct {
	HTTPClient *http.Client
}

func NewRevocationChecker(httpClients ...http.Client) *RevocationChecker {
	if len(httpClients) == 0 {
		return &RevocationChecker{HTTPClient: http.DefaultClient}
	} else {
		return &RevocationChecker{HTTPClient: &httpClients[0]}
	}
}

func (r RevocationChecker) CheckRevocationStatus(cert *x509.Certificate) (bool, error) {
	revoke.HTTPClient = r.HTTPClient
	revoked, _, err := revoke.VerifyCertificateError(cert)
	return revoked, err
}
