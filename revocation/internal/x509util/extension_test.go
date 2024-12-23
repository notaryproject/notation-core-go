package x509util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestFindExtensionByOID(t *testing.T) {
	oid1 := asn1.ObjectIdentifier{1, 2, 3, 4}
	oid2 := asn1.ObjectIdentifier{1, 2, 3, 5}
	extensions := []pkix.Extension{
		{Id: oid1, Value: []byte("value1")},
		{Id: oid2, Value: []byte("value2")},
	}

	tests := []struct {
		name       string
		oid        asn1.ObjectIdentifier
		extensions []pkix.Extension
		expected   *pkix.Extension
	}{
		{
			name:       "Extension found",
			oid:        oid1,
			extensions: extensions,
			expected:   &extensions[0],
		},
		{
			name:       "Extension not found",
			oid:        asn1.ObjectIdentifier{1, 2, 3, 6},
			extensions: extensions,
			expected:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindExtensionByOID(tt.oid, tt.extensions)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
