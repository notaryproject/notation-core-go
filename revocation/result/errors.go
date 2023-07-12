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

// Package result provides general objects that are used across revocation
package result

import (
	"fmt"
)

// InvalidChainError is returned when the certificate chain does not meet the
// requirements for a valid certificate chain
type InvalidChainError struct {
	Err error
}

func (e InvalidChainError) Error() string {
	msg := "invalid chain: expected chain to be correct and complete"
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}
