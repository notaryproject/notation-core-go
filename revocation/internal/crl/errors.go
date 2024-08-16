package crl

import "errors"

var (
	// ErrDeltaCRLNotChecked is returned when the CRL contains a delta CRL but
	// the delta CRLs are not checked
	ErrDeltaCRLNotChecked = errors.New("delta CRLs are not checked")
)
