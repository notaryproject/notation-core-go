// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"archive/tar"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// BaseCRL is the file name of the base CRL
	PathBaseCRL = "base.crl"

	// Metadata is the file name of the metadata
	PathMetadata = "metadata.json"
)

// Bundle is in memory representation of the Bundle tarball, including base CRL
// file and metadata file, which may be cached in the file system or other
// storage
//
// TODO: consider adding DeltaCRL field in the future
type Bundle struct {
	BaseCRL  *x509.RevocationList
	Metadata Metadata
}

// Metadata stores the metadata infomation of the CRL
//
// TODO: consider adding DeltaCRL field in the future
type Metadata struct {
	BaseCRL  FileInfo  `json:"base.crl"`
	CreateAt time.Time `json:"createAt"`
}

// FileInfo stores the URL and creation time of the file
type FileInfo struct {
	URL string `json:"url"`
}

// NewBundle creates a new CRL store with tarball format
func NewBundle(baseCRL *x509.RevocationList, url string) (*Bundle, error) {
	return &Bundle{
		BaseCRL: baseCRL,
		Metadata: Metadata{
			BaseCRL: FileInfo{
				URL: url,
			},
			CreateAt: time.Now(),
		},
	}, nil
}

// ParseBundleFromTarball parses the CRL blob from a tarball
//
// The tarball should contain two files:
// - base.crl: the base CRL in DER format
// - metadata.json: the metadata of the CRL
//
// example of metadata.json:
//
//	{
//	  "base.crl": {
//	    "url": "https://example.com/base.crl"
//	  },
//	  "createAt": "2024-07-20T00:00:00Z"
//	}
func ParseBundleFromTarball(data io.Reader) (*Bundle, error) {
	bundle := &Bundle{}

	// parse the tarball
	tar := tar.NewReader(data)
	for {
		header, err := tar.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, &BrokenFileError{
				Err: fmt.Errorf("failed to read tarball: %w", err),
			}
		}

		switch header.Name {
		case PathBaseCRL:
			// parse base.crl
			data, err := io.ReadAll(tar)
			if err != nil {
				return nil, err
			}

			var baseCRL *x509.RevocationList
			baseCRL, err = x509.ParseRevocationList(data)
			if err != nil {
				return nil, &BrokenFileError{
					Err: fmt.Errorf("failed to parse base CRL from tarball: %w", err),
				}
			}
			bundle.BaseCRL = baseCRL
		case PathMetadata:
			// parse metadata
			var metadata Metadata
			if err := json.NewDecoder(tar).Decode(&metadata); err != nil {
				return nil, &BrokenFileError{
					Err: fmt.Errorf("failed to parse CRL metadata from tarball: %w", err),
				}
			}
			bundle.Metadata = metadata
		default:
			return nil, &BrokenFileError{
				Err: fmt.Errorf("unexpected file in CRL tarball: %s", header.Name),
			}
		}
	}
	if err := bundle.validate(); err != nil {
		return nil, err
	}

	return bundle, nil
}

func (b *Bundle) validate() error {
	if b.BaseCRL == nil {
		return errors.New("base CRL is missing")
	}
	if b.Metadata.BaseCRL.URL == "" {
		return errors.New("base CRL URL is missing")
	}
	if b.Metadata.CreateAt.IsZero() {
		return errors.New("base CRL creation time is missing")
	}
	return nil
}

// SaveAsTar saves the CRL blob as a tarball, including the base CRL and
// metadata
//
// The tarball should contain two files:
// - base.crl: the base CRL in DER format
// - metadata.json: the metadata of the CRL
//
// example of metadata.json:
//
//	{
//	  "base.crl": {
//	    "url": "https://example.com/base.crl"
//	  },
//	  "createAt": "2024-06-30T00:00:00Z"
//	}
func (b *Bundle) SaveAsTarball(w io.Writer) (err error) {
	if err := b.validate(); err != nil {
		return err
	}

	tarWriter := tar.NewWriter(w)
	defer tarWriter.Close()

	// Add base.crl
	if err := addToTar(PathBaseCRL, b.BaseCRL.Raw, b.Metadata.CreateAt, tarWriter); err != nil {
		return err
	}

	// Add metadata.json
	metadataBytes, err := json.Marshal(b.Metadata)
	if err != nil {
		return err
	}
	return addToTar(PathMetadata, metadataBytes, time.Now(), tarWriter)
}

func addToTar(fileName string, data []byte, modTime time.Time, tw *tar.Writer) error {
	header := &tar.Header{
		Name:    fileName,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: modTime,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
