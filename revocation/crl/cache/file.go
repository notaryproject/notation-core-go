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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/internal/file"
)

const (
	// pathBaseCRL is the file name of the base CRL
	pathBaseCRL = "base.crl"

	// pathMetadata is the file name of the metadata
	pathMetadata = "metadata.json"

	// tempFileName is the prefix of the temporary file
	tempFileName = "notation-*"
)

// FileCache stores in a tarball format, which contains two files: base.crl and
// metadata.json. The base.crl file contains the base CRL in DER format, and the
// metadata.json file contains the metadata of the CRL.
//
// The cache builds on top of the UNIX file system to leverage the file system's
// atomic operations. The `rename` and `remove` operations will unlink the old
// file but keep the inode and file descriptor for existing processes to access
// the file. The old inode will be dereferenced when all processes close the old
// file descriptor. Additionally, the operations are proven to be atomic on
// UNIX-like platforms, so there is no need to handle file locking.
//
// NOTE: For Windows, the `open`, `rename` and `remove` operations need file
// locking to ensure atomicity. The current implementation does not handle
// file locking, so the concurrent write from multiple processes may be failed.
// Please do not use this cache in a multi-process environment on Windows.
//
// FileCache doesn't handle cache cleaning but provides the Delete and Clear
// methods to remove the CRLs from the file system.
type FileCache struct {
	// MaxAge is the maximum age of the CRLs cache. If the CRL is older than
	// MaxAge, it will be considered as expired.
	MaxAge time.Duration

	root string
}

// NewFileCache creates a new file system store
//
//   - root is the directory to store the CRLs.
func NewFileCache(root string) (*FileCache, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	return &FileCache{
		MaxAge: DefaultMaxAge,
		root:   root,
	}, nil
}

// Get retrieves the CRL bundle from the file system
//
// - if the key does not exist, return ErrNotFound
// - if the CRL is expired, return ErrCacheMiss
func (c *FileCache) Get(ctx context.Context, uri string) (bundle *Bundle, err error) {
	f, err := os.Open(filepath.Join(c.root, fileName(uri)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCacheMiss
		}
		return nil, err
	}
	defer f.Close()

	bundle, err = parseBundleFromTar(f)
	if err != nil {
		return nil, err
	}

	expires := bundle.Metadata.CachedAt.Add(c.MaxAge)
	if c.MaxAge > 0 && time.Now().After(expires) {
		// do not delete the file to maintain the idempotent behavior
		return nil, ErrCacheMiss
	}

	return bundle, nil
}

// Set stores the CRL bundle in the file system
func (c *FileCache) Set(ctx context.Context, uri string, bundle *Bundle) error {
	if err := bundle.Validate(); err != nil {
		return err
	}

	// save to temp file
	tempFile, err := os.CreateTemp("", tempFileName)
	if err != nil {
		return err
	}
	file.Using(tempFile, func(f *os.File) error {
		return saveTar(tempFile, bundle)
	})

	// rename is atomic on UNIX-like platforms
	return os.Rename(tempFile.Name(), filepath.Join(c.root, fileName(uri)))
}

// fileName returns the file name of the CRL bundle tarball
func fileName(url string) string {
	return hashURL(url) + ".tar"
}

// hashURL hashes the URL with SHA256 and returns the hex-encoded result
func hashURL(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:])
}

// parseBundleFromTar parses the CRL blob from a tarball
//
// The tarball should contain two files:
// - base.crl: the base CRL in DER format
// - metadata.json: the metadata of the CRL
//
// example of metadata.json:
//
//		{
//		  "baseCRL": {
//		    "url": "https://example.com/base.crl",
//	        "nextUpdate": "2024-07-20T00:00:00Z"
//		  },
//		  "cachedAt": "2024-07-20T00:00:00Z"
//		}
func parseBundleFromTar(data io.Reader) (*Bundle, error) {
	var bundle Bundle

	// parse the tarball
	tar := tar.NewReader(data)
	for {
		header, err := tar.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tarball: %w", err)
		}

		switch header.Name {
		case pathBaseCRL:
			// parse base.crl
			data, err := io.ReadAll(tar)
			if err != nil {
				return nil, err
			}

			baseCRL, err := x509.ParseRevocationList(data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse base CRL from tarball: %w", err)
			}
			bundle.BaseCRL = baseCRL
		case pathMetadata:
			// parse metadata
			var metadata Metadata
			if err := json.NewDecoder(tar).Decode(&metadata); err != nil {
				return nil, fmt.Errorf("failed to parse CRL metadata from tarball: %w", err)
			}
			bundle.Metadata = metadata
		}
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}

	return &bundle, nil
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
//	  "baseCRL": {
//	    "url": "https://example.com/base.crl",
//	    "nextUpdate": "2024-07-20T00:00:00Z"
//	  },
//	  "cachedAt": "2024-06-30T00:00:00Z"
//	}
func saveTar(w io.Writer, bundle *Bundle) (err error) {
	tarWriter := tar.NewWriter(w)
	defer func() {
		if cerr := tarWriter.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	// Add base.crl
	if err := addToTar(pathBaseCRL, bundle.BaseCRL.Raw, bundle.Metadata.CachedAt, tarWriter); err != nil {
		return err
	}

	// Add metadata.json
	metadataBytes, err := json.Marshal(bundle.Metadata)
	if err != nil {
		return err
	}
	return addToTar(pathMetadata, metadataBytes, bundle.Metadata.CachedAt, tarWriter)
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
