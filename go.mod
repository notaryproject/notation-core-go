module github.com/notaryproject/notation-core-go

go 1.23.0

require (
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/notaryproject/tspclient-go v1.0.0
	github.com/veraison/go-cose v1.3.0
	golang.org/x/crypto v0.36.0
)

require github.com/x448/float16 v0.8.4 // indirect

replace github.com/veraison/go-cose => github.com/shizhMSFT/go-cose v1.0.0-alpha.1.0.20250331071113-87052d1999cc
