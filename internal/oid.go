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

package oid

import "encoding/asn1"

// KeyUsage (id-ce-keyUsage) is defined in RFC 5280
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3
var KeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// ExtKeyUsage (id-ce-extKeyUsage) is defined in RFC 5280
//
// Reference: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12
var ExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// TimeStamping (id-kp-timeStamping) is defined in RFC 3161 2.3
//
// Reference: https://datatracker.ietf.org/doc/html/rfc3161#section-2.3
var TimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
