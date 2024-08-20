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

// Package crl provides the error message for processing crls.
package crl

import "github.com/notaryproject/notation-core-go/revocation/internal/crl"

var (
	// ErrDeltaCRLNotChecked is returned when the CRL contains a delta CRL but
	// the delta CRL is not checked
	ErrDeltaCRLNotChecked = crl.ErrDeltaCRLNotChecked
)
