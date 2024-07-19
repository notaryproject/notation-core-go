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

const (
	// BaseCRL is the file name of the base CRL
	BaseCRL = "base.crl"

	// Metadata is the file name of the metadata
	Metadata = "metadata.json"
)

// Store is an interface to store CRL
type Store interface {
	// Save saves the CRL
	Save() error
}

type BaseCRLStore interface {
	// BaseCRL returns the base CRL
	BaseCRL() *x509.RevocationList
}

// tarStore is a CRL store with tarball format
//
// The tarball contains:
// base.crl: the base CRL
// metadata.json: the metadata
type tarStore struct {
	baseCRL  *x509.RevocationList
	metadata metadata

	cache cache.Cache
}

type metadata struct {
	BaseCRL crlInfo `json:"base.crl"`
}

type crlInfo struct {
	URL string `json:"url"`
}

// NewTarStore creates a new CRL store with tarball format
func NewTarStore(baseCRL *x509.RevocationList, url string, cache cache.Cache) Store {
	return &tarStore{
		baseCRL: baseCRL,
		metadata: metadata{
			BaseCRL: crlInfo{
				URL: url,
			},
		},
		cache: cache}
}

// ParseTarStore parses the CRL tarball
func ParseTarStore(data io.Reader, cache cache.Cache) (*tarStore, error) {
	if cache == nil {
		return nil, errors.New("cache is required")
	}
	CRLTar := &tarStore{
		cache: cache,
	}

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
			var metadata metadata
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

	if CRLTar.metadata.BaseCRL.URL == "" {
		return nil, errors.New("base CRL's URL is missing from metadata.json")
	}

	return CRLTar, nil
}

func (c *tarStore) BaseCRL() *x509.RevocationList {
	return c.baseCRL
}

func (c *tarStore) Save() (err error) {
	baseURL := c.metadata.BaseCRL.URL
	if c.isCached(baseURL) {
		return nil
	}

	// create cache file
	w, err := c.cache.Set(tarStoreName(baseURL))
	if err != nil {
		return err
	}
	defer func() {
		if cerr := w.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if err := c.saveTar(w); err != nil {
		w.Cancel()
		return err
	}

	return nil
}

func (c *tarStore) saveTar(w cache.WriteCanceler) error {
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

func (c *tarStore) isCached(url string) bool {
	_, err := c.cache.Get(tarStoreName(url))
	return err == nil
}

func tarStoreName(url string) string {
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
