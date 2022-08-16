package jws

import (
	"math"
	"testing"
)

func Test_convertToMapError(t *testing.T) {
	_, err := convertToMap(math.Inf(1))
	if err == nil {
		t.Fatal("should cause error")
	}
}

func Test_generateJWSError(t *testing.T) {
	_, err := generateJWS("", nil, nil)
	cmpError(t, err.Error(), "unexpected error occurred while generating a JWS-JSON serialization from compact serialization")
}

func Test_getSignatureAlgorithmError(t *testing.T) {
	_, err := getSignatureAlgorithm("ES222")
	cmpError(t, err.Error(), `signature algorithm "ES222" is not supported`)
}
