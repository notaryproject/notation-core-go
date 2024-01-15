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

package cms

import "errors"

// ErrNotSignedData is returned if wrong content is provided when signed
// data is expected.
var ErrNotSignedData = errors.New("cms: content type is not signed-data")

// ErrAttributeNotFound is returned if attribute is not found in a given set.
var ErrAttributeNotFound = errors.New("attribute not found")

// Verification errors
var (
	ErrSignerInfoNotFound  = VerificationError{Message: "signerInfo not found"}
	ErrCertificateNotFound = VerificationError{Message: "certificate not found"}
)

// SyntaxError indicates that the ASN.1 data is invalid.
type SyntaxError struct {
	Message string
	Detail  error
}

// Error returns error message.
func (e SyntaxError) Error() string {
	msg := "cms: syntax error"
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.Detail != nil {
		msg += ": " + e.Detail.Error()
	}
	return msg
}

// Unwrap returns the internal error.
func (e SyntaxError) Unwrap() error {
	return e.Detail
}

// VerificationError indicates verification failures.
type VerificationError struct {
	Message string
	Detail  error
}

// Error returns error message.
func (e VerificationError) Error() string {
	msg := "cms: verification failure"
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.Detail != nil {
		msg += ": " + e.Detail.Error()
	}
	return msg
}

// Unwrap returns the internal error.
func (e VerificationError) Unwrap() error {
	return e.Detail
}
