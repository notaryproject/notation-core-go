package jws

import "testing"

func Test_jwtPayload_Valid(t *testing.T) {
	var payload jwtPayload
	err := payload.Valid()
	if err != nil {
		t.Fatal("JWS payload doesn't need to be validated")
	}
}
