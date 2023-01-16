package signaturetest

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/testhelper"
)

// GetTestLocalSigner returns the local signer with given keyType and size for testing
func GetTestLocalSigner(keyType signature.KeyType, size int) (signature.Signer, error) {
	switch keyType {
	case signature.KeyTypeEC:
		switch size {
		case 256:
			leafCertTuple := testhelper.GetECCertTuple(elliptic.P256())
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetECRootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		case 384:
			leafCertTuple := testhelper.GetECCertTuple(elliptic.P384())
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetECRootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		case 521:
			leafCertTuple := testhelper.GetECCertTuple(elliptic.P521())
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetECRootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		default:
			return nil, fmt.Errorf("key size not supported")
		}
	case signature.KeyTypeRSA:
		switch size {
		case 2048:
			leafCertTuple := testhelper.GetRSACertTuple(2048)
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetRSARootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		case 3072:
			leafCertTuple := testhelper.GetRSACertTuple(3072)
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetRSARootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		case 4096:
			leafCertTuple := testhelper.GetRSACertTuple(4096)
			certs := []*x509.Certificate{leafCertTuple.Cert, testhelper.GetRSARootCertificate().Cert}
			return signature.NewLocalSigner(certs, leafCertTuple.PrivateKey)
		default:
			return nil, fmt.Errorf("key size not supported")
		}
	default:
		return nil, fmt.Errorf("keyType not supported")
	}
}
