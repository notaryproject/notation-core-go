package timestamp

import (
	"testing"
)

func FuzzParseSignedToken(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSignedToken(data)
	})
}
