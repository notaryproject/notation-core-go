package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/notaryproject/notation-core-go/signature"
)

const (
	headerKeyExpiry      = "io.cncf.notary.expiry"
	headerKeySigningTime = "io.cncf.notary.signingTime"
	headerKeyCrit        = "crit"
	headerKeyAlg         = "alg"
	headerKeyCty         = "cty"
)

var signatureAlgJWSAlgMap = map[signature.Algorithm]string{
	signature.AlgorithmPS256: "PS256",
	signature.AlgorithmPS384: "PS384",
	signature.AlgorithmPS512: "PS512",
	signature.AlgorithmES256: "ES256",
	signature.AlgorithmES384: "ES384",
	signature.AlgorithmES512: "ES512",
}

var jwsAlgSignatureAlgMap = reverseMap(signatureAlgJWSAlgMap)

func reverseMap(m map[signature.Algorithm]string) map[string]signature.Algorithm {
	n := make(map[string]signature.Algorithm, len(m))
	for k, v := range m {
		n[v] = k
	}
	return n
}

func getSignedAttrs(req *signature.SignRequest, sigAlg signature.Algorithm) (map[string]interface{}, error) {
	extAttrs := make(map[string]interface{})
	var crit []string
	if !req.Expiry.IsZero() {
		crit = append(crit, headerKeyExpiry)
	}

	for _, elm := range req.ExtendedSignedAttributes {
		extAttrs[elm.Key] = elm.Value
		if elm.Critical {
			crit = append(crit, elm.Key)
		}
	}

	alg, err := getJWSAlgo(sigAlg)
	if err != nil {
		return nil, err
	}

	jwsProtectedHeader := jwsProtectedHeader{
		Algorithm:   alg,
		ContentType: req.Payload.ContentType,
		Critical:    crit,
		SigningTime: req.SigningTime.Truncate(time.Second),
	}
	if !req.Expiry.IsZero() {
		truncTime := req.Expiry.Truncate(time.Second)
		jwsProtectedHeader.Expiry = &truncTime
	}

	m, err := convertToMap(jwsProtectedHeader)
	if err != nil {
		return nil, &signature.MalformedSignRequestError{
			Msg: fmt.Sprintf("unexpected error occured while creating protected headers, Error: %s", err.Error())}
	}

	return mergeMaps(m, extAttrs), nil
}

func getJWSAlgo(alg signature.Algorithm) (string, error) {
	jwsAlg, ok := signatureAlgJWSAlgMap[alg]
	if !ok {
		return "", &signature.SignatureAlgoNotSupportedError{
			Alg: fmt.Sprintf("#%d", alg)}
	}

	return jwsAlg, nil
}

func convertToMap(i interface{}) (map[string]interface{}, error) {
	s, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(s, &m); err != nil {
		return nil, err
	}

	return m, nil
}

func mergeMaps(maps ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// getSigningMethod picks up a recommended algorithm for given public keys.
func getSigningMethod(key crypto.PublicKey) (jwt.SigningMethod, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return jwt.SigningMethodPS256, nil
		case 384:
			return jwt.SigningMethodPS384, nil
		case 512:
			return jwt.SigningMethodPS512, nil
		default:
			return nil, &signature.UnsupportedSigningKeyError{
				Msg: fmt.Sprintf("RSA%d", key.Size()),
			}
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().BitSize {
		case jwt.SigningMethodES256.CurveBits:
			return jwt.SigningMethodES256, nil
		case jwt.SigningMethodES384.CurveBits:
			return jwt.SigningMethodES384, nil
		case jwt.SigningMethodES512.CurveBits:
			return jwt.SigningMethodES512, nil
		default:
			return nil, &signature.UnsupportedSigningKeyError{
				Msg: fmt.Sprintf("ECDSA%d", key.Curve.Params().BitSize),
			}
		}
	}
	return nil, &signature.UnsupportedSigningKeyError{}
}
