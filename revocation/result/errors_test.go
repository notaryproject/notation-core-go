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

package result

import (
	"errors"
	"testing"
)

func TestInvalidChainError(t *testing.T) {
	t.Run("without_inner_error", func(t *testing.T) {
		err := &InvalidChainError{}
		expectedMsg := "invalid chain: expected chain to be correct and complete"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("inner_error", func(t *testing.T) {
		err := &InvalidChainError{Err: errors.New("inner error")}
		expectedMsg := "invalid chain: expected chain to be correct and complete: inner error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})
}

func TestOCSPFallbackError(t *testing.T) {
	t.Run("without_inner_error", func(t *testing.T) {
		err := &OCSPFallbackError{}
		expectedMsg := "the OCSP check result is of unknown status; fallback to CRL"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("with_ocsp_error", func(t *testing.T) {
		err := &OCSPFallbackError{OCSPErr: errors.New("ocsp error")}
		expectedMsg := "the OCSP check result is of unknown status; fallback to CRL; OCSP error: ocsp error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("with_crl_error", func(t *testing.T) {
		err := &OCSPFallbackError{CRLErr: errors.New("crl error")}
		expectedMsg := "the OCSP check result is of unknown status; fallback to CRL; CRL error: crl error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})

	t.Run("with_both_errors", func(t *testing.T) {
		err := &OCSPFallbackError{OCSPErr: errors.New("ocsp error"), CRLErr: errors.New("crl error")}
		expectedMsg := "the OCSP check result is of unknown status; fallback to CRL; OCSP error: ocsp error; CRL error: crl error"

		if err.Error() != expectedMsg {
			t.Errorf("Expected %v but got %v", expectedMsg, err.Error())
		}
	})
}
