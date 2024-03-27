module github.com/notaryproject/notation-core-go

go 1.21

require (
	github.com/fxamacker/cbor/v2 v2.6.0
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/notaryproject/tspclient-go v0.0.0-20240122083733-a373599795a2
	github.com/veraison/go-cose v1.1.0
	golang.org/x/crypto v0.21.0
)

require github.com/x448/float16 v0.8.4 // indirect

replace github.com/notaryproject/tspclient-go => github.com/Two-Hearts/tspclient-go v0.0.0-20240322031047-c33159600668
