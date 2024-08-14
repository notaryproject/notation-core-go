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
	"crypto/x509"
	"errors"
	"time"
)

const (
	// BaseCRL is the file name of the base CRL
	PathBaseCRL = "base.crl"

	// Metadata is the file name of the metadata
	PathMetadata = "metadata.json"
)

// CRLMetadata stores the URL and creation time of the file
type CRLMetadata struct {
	URL string `json:"url"`
}

// Metadata stores the metadata infomation of the CRL
//
// TODO: consider adding DeltaCRL field in the future
type Metadata struct {
	// BaseCRL stores the URL of the base CRL
	BaseCRL CRLMetadata `json:"base.crl"`

	// CreateAt stores the creation time of the CRL bundle. This is different
	// from the `ThisUpdate` field in the CRL. The `ThisUpdate` field in the CRL
	// is the time when the CRL was generated, while the `CreateAt` field is for
	// caching purpose, indicating the start of cache effective period.
	CreateAt time.Time `json:"createAt"`
}

// Bundle is in memory representation of the Bundle tarball, including base CRL
// file and metadata file, which may be cached in the file system or other
// storage
//
// TODO: consider adding DeltaCRL field in the future
type Bundle struct {
	BaseCRL  *x509.RevocationList
	Metadata Metadata
}

func (b *Bundle) Validate() error {
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
