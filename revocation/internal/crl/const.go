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

const (
	// RFC 5280, 5.3.1
	// CRLReason ::= ENUMERATED {
	//   unspecified             (0),
	//   keyCompromise           (1),
	//   cACompromise            (2),
	//   affiliationChanged      (3),
	//   superseded              (4),
	//   cessationOfOperation    (5),
	//   certificateHold         (6),
	//        -- value 7 is not used
	//   removeFromCRL           (8),
	//   privilegeWithdrawn      (9),
	//   aACompromise           (10) }
	reasonCodeCertificateHold = 6
	reasonCodeRemoveFromCRL   = 8
)
