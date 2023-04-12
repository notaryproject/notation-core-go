// Package base provides general objects that are used across revocation
package base

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
