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

package x509util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
)

// FindExtensionByOID finds the extension by the given OID.
func FindExtensionByOID(extensions []pkix.Extension, oid asn1.ObjectIdentifier) *pkix.Extension {
	idx := slices.IndexFunc(extensions, func(ext pkix.Extension) bool {
		return ext.Id.Equal(oid)
	})
	if idx < 0 {
		return nil
	}
	return &extensions[idx]
}
