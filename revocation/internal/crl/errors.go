package crl

import "errors"

var (
	ErrDeltaCRLNotChecked = errors.New("delta CRLs are not checked")
)
