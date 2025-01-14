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

// Package x509util provides the method to validate the certificate chain for a
// specific purpose, including code signing and timestamping. It also provides
// the method to find the extension by the given OID.
package x509util

import (
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/revocation/purpose"
	"github.com/notaryproject/notation-core-go/revocation/result"
	coreX509 "github.com/notaryproject/notation-core-go/x509"
)

// ValidateChain checks the certificate chain for a specific purpose, including
// code signing and timestamping.
func ValidateChain(certChain []*x509.Certificate, certChainPurpose purpose.Purpose) error {
	switch certChainPurpose {
	case purpose.CodeSigning:
		// Since ValidateCodeSigningCertChain is using authentic signing time,
		// signing time may be zero.
		// Thus, it is better to pass nil here than fail for a cert's NotBefore
		// being after zero time
		if err := coreX509.ValidateCodeSigningCertChain(certChain, nil); err != nil {
			return result.InvalidChainError{Err: err}
		}
	case purpose.Timestamping:
		if err := coreX509.ValidateTimestampingCertChain(certChain); err != nil {
			return result.InvalidChainError{Err: err}
		}
	default:
		return result.InvalidChainError{Err: fmt.Errorf("unsupported certificate chain purpose %v", certChainPurpose)}
	}
	return nil
}
