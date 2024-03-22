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

package jws

import (
	"encoding/json"
	"math"
	"testing"
)

func Test_convertToMap(t *testing.T) {
	type S struct {
		A string
		B int
		C float64
	}
	t.Run("invalid value", func(t *testing.T) {
		_, err := convertToMap(math.Inf(1))
		if err == nil {
			t.Fatal("should cause error")
		}
	})

	t.Run("normal case", func(t *testing.T) {
		testStruct := S{
			A: "test string",
			B: 1,
			C: 1.1,
		}
		// generate map
		m, err := convertToMap(&testStruct)
		checkNoError(t, err)

		// convert map to struct
		bytes, err := json.Marshal(m)
		checkNoError(t, err)

		var newStruct S
		err = json.Unmarshal(bytes, &newStruct)
		checkNoError(t, err)

		// check new struct equal with original struct
		if newStruct != testStruct {
			t.Fatal("convertToMap error")
		}
	})
}

func Test_generateJWSError(t *testing.T) {
	_, err := generateJWS("", nil, "", nil)
	checkErrorEqual(t, "unexpected error occurred while generating a JWS-JSON serialization from compact serialization", err.Error())
}

func Test_getSignatureAlgorithmError(t *testing.T) {
	_, err := getSignatureAlgorithm("ES222")
	checkErrorEqual(t, `signature algorithm "ES222" is not supported`, err.Error())
}
