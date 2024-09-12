package revocation

import "testing"

func TestMethods(t *testing.T) {
	t.Run("MethodUnknown", func(t *testing.T) {
		if MethodUnknown != 0 {
			t.Errorf("Expected %d but got %d", 0, MethodUnknown)
		}
	})
	t.Run("MethodOCSP", func(t *testing.T) {
		if MethodOCSP != 1 {
			t.Errorf("Expected %d but got %d", 1, MethodOCSP)
		}
	})
	t.Run("MethodCRL", func(t *testing.T) {
		if MethodCRL != 2 {
			t.Errorf("Expected %d but got %d", 1, MethodCRL)
		}
	})
	t.Run("MethodOCSPFallbackCRL", func(t *testing.T) {
		if MethodOCSPFallbackCRL != 3 {
			t.Errorf("Expected %d but got %d", 3, MethodOCSPFallbackCRL)
		}
	})
}
