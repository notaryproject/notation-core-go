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

package ocsp

import "github.com/notaryproject/notation-core-go/revocation/internal/ocsp"

type (
	// RevokedError is returned when the certificate's status for OCSP is
	// ocsp.Revoked
	RevokedError = ocsp.RevokedError

	// UnknownStatusError is returned when the certificate's status for OCSP is
	// ocsp.Unknown
	UnknownStatusError = ocsp.UnknownStatusError

	// GenericError is returned when there is an error during the OCSP revocation
	// check, not necessarily a revocation
	GenericError = ocsp.GenericError

	// NoServerError is returned when the OCSPServer is not specified.
	NoServerError = ocsp.NoServerError

	// TimeoutError is returned when the connection attempt to an OCSP URL exceeds
	// the specified threshold
	TimeoutError = ocsp.TimeoutError
)
