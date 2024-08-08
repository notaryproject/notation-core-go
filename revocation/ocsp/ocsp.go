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

// Package ocsp provides methods for checking the OCSP revocation status of a
// certificate chain, as well as errors related to these checks
package ocsp

import (
	"github.com/notaryproject/notation-core-go/revocation/internal/ocsp"
)

// Options specifies values that are needed to check OCSP revocation
type Options = ocsp.Options

// CheckStatus checks OCSP based on the passed options and returns an array of
// result.CertRevocationResult objects that contains the results and error. The
// length of this array will always be equal to the length of the certificate
// chain.
var CheckStatus = ocsp.CheckStatus
