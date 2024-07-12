package crl

import (
	"archive/tar"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/crl/cache"
)

const BaseCRL = "base.crl"
const Metadata = "metadata.json"

type CRLStore interface {
	BaseCRL() *x509.RevocationList
	Metadata() map[string]string
	SetBaseCRL(baseCRL *x509.RevocationList, url string)
	Save() error
}

type crlTarStore struct {
	baseCRL  *x509.RevocationList
	metadata map[string]string

	cache cache.Cache
}

func NewCRLTarStore(baseCRL *x509.RevocationList, url string, cache cache.Cache) CRLStore {
	return &crlTarStore{
		baseCRL:  baseCRL,
		metadata: map[string]string{BaseCRL: url},
		cache:    cache}
}

// ParseCRLTar parses the CRL tarball
func ParseCRLTar(data io.Reader) (*crlTarStore, error) {
	CRLTar := &crlTarStore{}

	// parse the tarball
	tar := tar.NewReader(data)

	for {
		header, err := tar.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		switch header.Name {
		case BaseCRL:
			// parse base.crl
			data, err := io.ReadAll(tar)
			if err != nil {
				return nil, err
			}

			var baseCRL *x509.RevocationList
			baseCRL, err = x509.ParseRevocationList(data)
			if err != nil {
				return nil, err
			}

			CRLTar.baseCRL = baseCRL
		case Metadata:
			// parse metadata
			metadata := make(map[string]string)
			if err := json.NewDecoder(tar).Decode(&metadata); err != nil {
				return nil, err
			}

			CRLTar.metadata = metadata

		default:
			return nil, fmt.Errorf("unknown file in tarball: %s", header.Name)
		}
	}

	if CRLTar.baseCRL == nil {
		return nil, errors.New("base.crl is missing")
	}

	if CRLTar.metadata == nil {
		return nil, errors.New("metadata.json is missing")
	}

	if _, ok := CRLTar.metadata[BaseCRL]; !ok {
		return nil, errors.New("base.crl URL is missing")
	}

	return CRLTar, nil
}

func (c *crlTarStore) BaseCRL() *x509.RevocationList {
	return c.baseCRL
}

func (c *crlTarStore) Metadata() map[string]string {
	return c.metadata
}

func (c *crlTarStore) SetBaseCRL(baseCRL *x509.RevocationList, url string) {
	c.baseCRL = baseCRL

	if c.metadata == nil {
		c.metadata = make(map[string]string)
	}
	c.metadata[BaseCRL] = url
}

func (c *crlTarStore) Save() error {
	baseCRLURL, ok := c.metadata[BaseCRL]
	if !ok {
		return errors.New("base.crl URL is missing")
	}

	// create cache file
	w, err := c.cache.Set(buildTarName(baseCRLURL))
	if err != nil {
		return err
	}
	defer w.Close()

	if err := c.saveTar(w); err != nil {
		w.Cancel()
		return err
	}

	return nil
}

func (c *crlTarStore) saveTar(w cache.WriteCanceler) error {
	tarWriter := tar.NewWriter(w)
	// Add base.crl
	if err := addToTar(BaseCRL, c.baseCRL.Raw, tarWriter); err != nil {
		return err
	}

	// Add metadataBytes.json
	metadataBytes, err := json.Marshal(c.metadata)
	if err != nil {
		return err
	}
	return addToTar(Metadata, metadataBytes, tarWriter)
}

func buildTarName(url string) string {
	return hashURL(url) + ".tar"
}

// hashURL hashes the URL with SHA256 and returns the hex-encoded result
func hashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}

func addToTar(fileName string, data []byte, tw *tar.Writer) error {
	header := &tar.Header{
		Name:    fileName,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
