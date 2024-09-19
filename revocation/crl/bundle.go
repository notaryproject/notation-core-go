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

package crl

import "crypto/x509"

// Bundle is a collection of CRLs, including base and delta CRLs
type Bundle struct {
	// BaseCRL is the parsed base CRL
	BaseCRL *x509.RevocationList

	// DeltaCRL is the parsed delta CRL
	//
	// TODO: support delta CRL
	// It will always be nil until we support delta CRL
	DeltaCRL *x509.RevocationList
}
