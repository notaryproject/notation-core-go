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

// Package purpose provides purposes of the certificate chain whose revocation
// status is checked
package purpose

// Purpose is an enum for purpose of the certificate chain whose revocation
// status is checked
type Purpose int

const (
	// CodeSigning means the certificate chain is a code signing chain
	CodeSigning Purpose = iota

	// Timestamping means the certificate chain is a timestamping chain
	Timestamping
)
