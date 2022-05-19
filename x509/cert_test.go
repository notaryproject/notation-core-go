package x509

import (
	"crypto/x509"
	"testing"
)

var signingCertPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIEbDCCA1SgAwIBAgIRAMwVT2E9fwmK0y/2/6FmIdowDQYJKoZIhvcNAQEMBQAw\n" +
	"TTEbMBkGA1UECgwSTWFyc3VwaWFsIFZlbnR1cmVzMRAwDgYDVQQLDAdXYWxsYWJ5\n" +
	"MRwwGgYDVQQDDBNqZGRvbmFzLXN1Ym9yZGluYXRlMCAXDTIxMTExMTIxNDAwMVoY\n" +
	"DzIxMTgxMTExMjI0MDAxWjCBnDETMBEGA1UECAwKV2FzaGluZ3RvbjELMAkGA1UE\n" +
	"BhMCVVMxITAfBgkqhkiG9w0BCQEWEmpkZG9uYXNAYW1hem9uLmNvbTEPMA0GA1UE\n" +
	"CwwGU2lnbmVyMRAwDgYDVQQDDAdXYWxsYWJ5MRAwDgYDVQQHDAdTZWF0dGxlMSAw\n" +
	"HgYDVQQKDBdBbWF6b24uY29tIFNlcnZpY2VzIExMQzCCAaIwDQYJKoZIhvcNAQEB\n" +
	"BQADggGPADCCAYoCggGBAK6fQCIVnXq80y26ZXOzcwpOb9pLfgEWJ+Niol/e2Yls\n" +
	"KxxJBwCW8dlvZjCfqQU6mhAFpBULUX8iql33m0Wkqhw7BRxRNB69wTVZ7ceMUMh4\n" +
	"0fvQF3yGzIPQptfD/yjPEwoF73mRdQighWKc/dm4mjUEPmWYcv/TMi4D7X9mwrcn\n" +
	"+DzE9yvxa78dooYWp96lsZdpLOIuK7nJQc2UTOolMsXgRMti98N1CEpiT2V1TCA2\n" +
	"1FLkiMDJHrNRC1oASGtR3cMeljpNAOn4rZkgVziOw9eST4wzHmmHhoTDcNQMY8wg\n" +
	"kAYdSoekFeZl8U5xmZEtOwG8CxtG0Jl6ZRw0CBZNYQIRw+fbvYSUpOZuzyXGiwGI\n" +
	"FURCW/NtYlnA+9GEfLrBc8WzPRQ0NFbbh7f/A38mUcvM/nhVGBciNf8gmb4EKn94\n" +
	"4Lk90PH0ZOYA9QlrwvFjGTS2Fa/yrQFXTJBg7NiU1qGs4eIr2sQ14UC6l4+yEv2+\n" +
	"ZSC8Y+6YmoRtcxguiwMkpwIDAQABo3UwczAJBgNVHRMEAjAAMB8GA1UdIwQYMBaA\n" +
	"FHfSbC3GKHiWYMa4GxmIhPL23eDzMB0GA1UdDgQWBBT4ZB4Kh1hkWwQSWvGf2/NQ\n" +
	"bOAdRDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwMwDQYJ\n" +
	"KoZIhvcNAQEMBQADggEBAF1ldBzEjXmZqZhnQjR9U/0eN4FUyLiGTJ+bPLejSqW6\n" +
	"Co7w0R7vXgKXew2VdmU0mbOGGBi1TLITX35YPsxLe8QuaYqHIaT9/tdHlW1KFl/g\n" +
	"CH/2Q6GvoYG3VuU6zERmMBFVrtctVb9TONJPh4T5niQ/IbCoXAi7VGLtARoLjLA0\n" +
	"2Z0fnvsl9VCnQw/H4+QbTYc48laZu0KlLRmMMk6mngMe5pv57yjnacls3mV6aTBc\n" +
	"aIF2IH4NegRGg+IMpwg7JG48fwHDi8gr7vhyJgApsZf852VtyO2BpcMWfEduA8Uw\n" +
	"lOW/6LMrMl7X14etsObs9kIozM+rbyQFs3rtu/yOp24=\n" +
	"-----END CERTIFICATE-----"

var intermediateCertPem1 = "-----BEGIN CERTIFICATE-----\n" +
	"MIIDjjCCAnagAwIBAgIRAPIXzmfl4PSC7QkHjRBQqQEwDQYJKoZIhvcNAQELBQAw\n" +
	"TjEbMBkGA1UECgwSTWFyc3VwaWFsIFZlbnR1cmVzMRAwDgYDVQQLDAdXYWxsYWJ5\n" +
	"MR0wGwYDVQQDDBRqZGRvbmFzLWludGVybWVkaWF0ZTAgFw0yMTExMTEyMTA1MzRa\n" +
	"GA8yMTE5MTExMTIyMDUzNFowTTEbMBkGA1UECgwSTWFyc3VwaWFsIFZlbnR1cmVz\n" +
	"MRAwDgYDVQQLDAdXYWxsYWJ5MRwwGgYDVQQDDBNqZGRvbmFzLXN1Ym9yZGluYXRl\n" +
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlUsfsSqb2qGZKpReXoBR\n" +
	"75Qh8Yx4Y+prhjEivj23Fhd+Yzs84UTSBBwsesp3EFmFvuYU76B3DFjBpp7g6gsf\n" +
	"4JEX7OsE5/hAWjTYQJky6EDBDgDZUdimowjpDUvjGNt/nQWnPW5FtiuNZ8jg3cCY\n" +
	"13oirEok0KSO17bsLV8oCY18JwwqjNTCuqVwpppLeBNIPxyUXgwA3oo1g/TV8uog\n" +
	"BGGEQCGJtKQ1Q4X4P5i7q+pmZXG0kuEXZBzOKLcrsFwDAizq+2bkUFdUlGX/CWGU\n" +
	"F7E275zkIVpDtHqLEXwb5MS67t+7NVpjBojwJ4aP60TjyROGJ0kqgvjEN5j1H2SF\n" +
	"pQIDAQABo2YwZDASBgNVHRMBAf8ECDAGAQH/AgECMB8GA1UdIwQYMBaAFB5Xa5SX\n" +
	"FNLNj2A1XBzaWsu+++0fMB0GA1UdDgQWBBR30mwtxih4lmDGuBsZiITy9t3g8zAO\n" +
	"BgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggEBACeFU+vokcPIJDQl6tWP\n" +
	"pnDBMeb93ZxIwjRarPsKRSthyGOH19243y6kBqC4A1nTHn35iWeAFTso61B3DkOW\n" +
	"KwOsM2fQrxfqDR9UnwQMO8+R9KudXRi0lXrPm8h0ZnKMkaTCcpMNOtwaDVR1/1u/\n" +
	"SdbKz19Tug4U2L9swhSHSXbB49vMiAUvMv5t8DOzdR+v91pYxDRfNKPWpiwai9Bn\n" +
	"7mJjCoX6a42d/Bkt+Yk8cUWe4Mx3/zHiwUl7F9qqVJBOl1G0bL9fRmTvNIIU2fFy\n" +
	"gQ42dlzhPBTvPfGAri7Mg55DAvqlAx8uAxfsyAz/RCkl92R7XRKXAJfC7TeBxYG0\n" +
	"kgY=\n" +
	"-----END CERTIFICATE-----"

var intermediateCertPem2 = "-----BEGIN CERTIFICATE-----\n" +
	"MIIDhzCCAm+gAwIBAgIRAMWGQ2p5xVw9U8Olod0yYdAwDQYJKoZIhvcNAQEMBQAw\n" +
	"RjEbMBkGA1UECgwSTWFyc3VwaWFsIFZlbnR1cmVzMRAwDgYDVQQLDAdXYWxsYWJ5\n" +
	"MRUwEwYDVQQDDAxqZGRvbmFzLXJvb3QwIBcNMjExMTExMjEwNDI5WhgPMjEyMDEx\n" +
	"MTEyMjA0MjlaME4xGzAZBgNVBAoMEk1hcnN1cGlhbCBWZW50dXJlczEQMA4GA1UE\n" +
	"CwwHV2FsbGFieTEdMBsGA1UEAwwUamRkb25hcy1pbnRlcm1lZGlhdGUwggEiMA0G\n" +
	"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQDeA3TY5H0Pli72f1zFulGWFIBqcZ\n" +
	"ZWzTO6mDvnyHlQam7XibFCuj49DtHN+z6cW5+ncG9NcslE7Yfk7vGlRJnMfnGUae\n" +
	"rg9sHycOjZC6LmQlHMKY+ZEPvWMRpqzakapfn2IpQCbK1p/ynjcvC8MBZLDcIrSE\n" +
	"3FxB+RXbufvcnd+P0bS+tkhO2aVMM0+WbDFL7xvPepEO22pXVEsDHFlev0xaSW1I\n" +
	"oPOJORr9Z6EQQCX2ZaP2rTRuGO1L7p/Uds3R3TFGEF6DWfyCY4j3zy0IARFofFV2\n" +
	"PVNpf/n+5vvsy8BL2siOrK8G2/sKw1HmuIV7nVrZp9oFYgIPeaTNZLBvAgMBAAGj\n" +
	"ZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQMwHwYDVR0jBBgwFoAU+ZG3pNX5GqqXjcga\n" +
	"UtA2LH+wo5EwHQYDVR0OBBYEFB5Xa5SXFNLNj2A1XBzaWsu+++0fMA4GA1UdDwEB\n" +
	"/wQEAwIBhjANBgkqhkiG9w0BAQwFAAOCAQEAeNhKFwsAb8ka2N+xQn/CPGFRrys9\n" +
	"D5M2m+DqufeIzBgPNgFQ0FDlxv0O+J8QEA2Y7HoEvbUr1iOCByMYpVCzk/iwMy+c\n" +
	"ANGFxcOSwNx8YFSL+Jm66ByH0hYwYvQb8y2Ecs/PqqnrcjIGYdwYnN5Jdj6bWQie\n" +
	"hX5ZQ2nbr0vNGDes8QASk6NiaVsZS9SQd3FfR9v08HwpbjyFNLsRmxgsshH4sRDp\n" +
	"hzIePqkPUy2d23WfZA1yxfKD352ZF6HeIi12w9u2JSv0b/OlTCgGPNYbQ83pOmbU\n" +
	"EBiMnOT/pldy6EUv06SDc3IonqrWc94rtzIrq3tUMfadfjyWM5qhLY4nmw==\n" +
	"-----END CERTIFICATE-----"

var rootCertPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIDWjCCAkKgAwIBAgIQOFj621GWxnv9muaHIqCxhDANBgkqhkiG9w0BAQwFADBG\n" +
	"MRswGQYDVQQKDBJNYXJzdXBpYWwgVmVudHVyZXMxEDAOBgNVBAsMB1dhbGxhYnkx\n" +
	"FTATBgNVBAMMDGpkZG9uYXMtcm9vdDAgFw0yMTExMTEyMDU3NDVaGA8yMTIxMTEx\n" +
	"MTIxNTc0NVowRjEbMBkGA1UECgwSTWFyc3VwaWFsIFZlbnR1cmVzMRAwDgYDVQQL\n" +
	"DAdXYWxsYWJ5MRUwEwYDVQQDDAxqZGRvbmFzLXJvb3QwggEiMA0GCSqGSIb3DQEB\n" +
	"AQUAA4IBDwAwggEKAoIBAQCq0PKqLowkHF3y8gSlpuv+B/YZuu4vkbb4XTlJLJj1\n" +
	"1YWU9y1kZ5epMVFVxc8PsYKbBDzTFRsi+gB1totJ8Bda8QNI9I7XFLx1G0prwBF4\n" +
	"bPxsVbvqHv74f1EVIIEhuGDnwBmWF9N/W5eK8xSV1vBEhe0eqSoXbRRIvaj0Rgd0\n" +
	"mXd6nz33HCCrJqmUFVEAELMJgBwS77+TrP4BtjaXFNCCb6ZYVTRmKsQFaLe4md/x\n" +
	"uxJw/TGSYo37DYBfPYB5sYN3T+a7nsxfzYS9p4ETyJ08t7VHN5vAKB3bIaEQlsJN\n" +
	"UDzlNMq6cEmjVDb0Mf9wc9zqt+bM+CjL9LeuyS2OcBQjAgMBAAGjQjBAMA8GA1Ud\n" +
	"EwEB/wQFMAMBAf8wHQYDVR0OBBYEFPmRt6TV+Rqql43IGlLQNix/sKORMA4GA1Ud\n" +
	"DwEB/wQEAwIBhjANBgkqhkiG9w0BAQwFAAOCAQEAH+XQ7rYewAb7YCx+wbg5E2Cf\n" +
	"Ea3o9LW3Np3W73rznozROBwje5Wwo3AjcZh49/0Q3Bro2gbo9l5XPErui6x5KmnM\n" +
	"Vg3Sely0awnM/yyMzypGbCSP/zMfCf8AysIY3uIcNcPBpJV3ySC60kyLTGnpszBH\n" +
	"S9jKV7vnpjCj4Kov8IZIom5U4gsKAxLamigTAsj46lLOW0HO2Jc08iaRGGtEAK2w\n" +
	"k2CCGO9eo5Jt29CHCU0F2SPndoUOwPBklPkx2I/NnG1HiWnbHckfCXmp65hdFfAS\n" +
	"qnZOe/FBVeXCw4ONwEL74u7UgGy3WIfGWBKI4J9VOjRn9ilF5v5TQq7QIH6mMQ==\n" +
	"-----END CERTIFICATE-----"

var unrelatedCertPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIID3jCCAsagAwIBAgIQc1lt0WMdGtBxWxu8MSY4qjANBgkqhkiG9w0BAQwFADCB\n" +
	"iDELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEk1hcnN1cGlhbCBWZW50dXJlczEZMBcG\n" +
	"A1UECwwQQVdTIENyeXB0b2dyYXBoeTETMBEGA1UECAwKV2FzaGluZ3RvbjEaMBgG\n" +
	"A1UEAwwRaW1idXJnZXItZGV2LXJvb3QxEDAOBgNVBAcMB1NlYXR0bGUwHhcNMjEx\n" +
	"MTAxMTYxNDE1WhcNMzExMTAxMTcxNDE1WjCBiDELMAkGA1UEBhMCVVMxGzAZBgNV\n" +
	"BAoMEk1hcnN1cGlhbCBWZW50dXJlczEZMBcGA1UECwwQQVdTIENyeXB0b2dyYXBo\n" +
	"eTETMBEGA1UECAwKV2FzaGluZ3RvbjEaMBgGA1UEAwwRaW1idXJnZXItZGV2LXJv\n" +
	"b3QxEDAOBgNVBAcMB1NlYXR0bGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
	"AoIBAQDaAhcK26E2LR6mNaFywj0DPS8mjqqpg31hH9QwqxDwLX99gJYyQ4GkiiSA\n" +
	"SGaX3BFFfPUd2aVqKH4weLPseW4MsFbWFNV9LxUlm9SQRIPAbtmBcpPyzjOgRoLK\n" +
	"3bvfiSl0Wtgh+OpK/jqT459tJEOuV1iUmdXECsi6N4pXmhrya7T7Y5y4dqQxdXZk\n" +
	"d0a2EeJjwvoxrLpJxDlubwpN4HjSXKlPMsYztmddNY7g8u5YM7xkE0PBrMjkU4pK\n" +
	"sIJB2KhckpzTrYzfwzEWYQctkAzg/1CT8/w5OB2lX4KZsathjbKOOzC2bfrKvgBi\n" +
	"SgnViyifCPTDtsoYB7joCe54vSVTAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8w\n" +
	"HQYDVR0OBBYEFHiW4ml/zTKWsN7tNUR69IbuWiZZMA4GA1UdDwEB/wQEAwIBhjAN\n" +
	"BgkqhkiG9w0BAQwFAAOCAQEAHAzMMBqMIjg/xn8PxinEYwjdphkORMUHCe3SKNKF\n" +
	"rVKlYhbQVENFp+ZuXmZaHTeq8fOKaAy5KDbpMR7t9pp9VQJPujDD/4Zz37Cbk8YY\n" +
	"DBl6ewFXMJZMzDP7crW+24Prmv4TAfGzPSNYPWtuMQVc6mkpG9uVvATiTU1+reX6\n" +
	"uFwjUKoWaAcNlB1qeYioSQJE5v0X+t16V5nb589FwSQ24UClDFOFCDUC2Lkd5SWu\n" +
	"zgrzP9O6O7JWZuNhRcAYrDjrR2+KCLFE7x+fzvHIGZ15hrqaKJEkcNjypqkgx2p8\n" +
	"38n/tklZaJZ5jjhV1aVz0rZqzXpxg3c9lS9r83gmaWP3/w==\n" +
	"-----END CERTIFICATE-----"

var signingCert = parseCertificateFromString(signingCertPem)
var intermediateCert1 = parseCertificateFromString(intermediateCertPem1)
var intermediateCert2 = parseCertificateFromString(intermediateCertPem2)
var rootCert = parseCertificateFromString(rootCertPem)
var unrelatedCert = parseCertificateFromString(unrelatedCertPem)

func TestValidCertificateChain(t *testing.T) {
	certChain := []*x509.Certificate{signingCert, intermediateCert1, intermediateCert2, rootCert}

	err := ValidateCertChain(certChain)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFailEmptyChain(t *testing.T) {
	certChain := []*x509.Certificate{signingCert}

	err := ValidateCertChain(certChain)
	assertErrorEqual("certificate chain must contain at least two certificates", err, t)
}

func TestFailChainNotEndingInRoot(t *testing.T) {
	certChain := []*x509.Certificate{signingCert, intermediateCert1, intermediateCert2}

	err := ValidateCertChain(certChain)
	assertErrorEqual("certificate chain must end with a root certificate (root certificates are self-signed)", err, t)
}

func TestFailChainNotOrdered(t *testing.T) {
	certChain := []*x509.Certificate{signingCert, intermediateCert2, intermediateCert1, rootCert}

	err := ValidateCertChain(certChain)
	assertErrorEqual("signature on certificate \"CN=Wallaby,OU=Signer,O=Amazon.com Services LLC,L=Seattle,ST=Washington,C=US,1.2.840.113549.1.9.1=#0c126a64646f6e617340616d617a6f6e2e636f6d\" is not issued by \"CN=jddonas-intermediate,OU=Wallaby,O=Marsupial Ventures\"", err, t)
}

func TestFailChainWithUnrelatedCert(t *testing.T) {
	certChain := []*x509.Certificate{signingCert, unrelatedCert, intermediateCert2, rootCert}

	err := ValidateCertChain(certChain)
	assertErrorEqual("signature on certificate \"CN=Wallaby,OU=Signer,O=Amazon.com Services LLC,L=Seattle,ST=Washington,C=US,1.2.840.113549.1.9.1=#0c126a64646f6e617340616d617a6f6e2e636f6d\" is not issued by \"CN=imburger-dev-root,OU=AWS Cryptography,O=Marsupial Ventures,L=Seattle,ST=Washington,C=US\"", err, t)
}

func TestFailChainWithDuplicateRepeatedRoots(t *testing.T) {
	certChain := []*x509.Certificate{rootCert, rootCert, rootCert}

	err := ValidateCertChain(certChain)
	assertErrorEqual("certificate chain must not contain self-signed intermediate certificates", err, t)
}

func TestRootCertIdentified(t *testing.T) {
	if isSelfSigned(signingCert) || isSelfSigned(intermediateCert1) ||
		isSelfSigned(intermediateCert2) || !isSelfSigned(rootCert) {
		t.Fatal("Root cert was not correctly identified")
	}
}

func parseCertificateFromString(certPem string) *x509.Certificate {
	stringAsBytes := []byte(certPem)
	cert, _ := parseCertificates(stringAsBytes)
	return cert[0]
}

func assertErrorEqual(expected string, err error, t *testing.T) {
	if expected != err.Error() {
		t.Fatalf("Expected error \"%v\" but was \"%v\"", expected, err)
	}
}

func TestLoadPemFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/pem.crt")
	verifyNoError(t, err)
	verifyNumCerts(t, certs, 1)
}

func TestLoadMultiPemFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/multi-pem.crt")
	verifyNoError(t, err)
	verifyNumCerts(t, certs, 2)
}

func TestLoadDerFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/der.der")
	verifyNoError(t, err)
	verifyNumCerts(t, certs, 1)
}

func TestLoadMultiDerFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/multi-der.der")
	verifyNoError(t, err)
	verifyNumCerts(t, certs, 2)
}

func TestLoadInvalidFile(t *testing.T) {
	certs, err := ReadCertificateFile("testdata/invalid")
	if err == nil {
		t.Fatalf("invalid file should throw an error")
	}
	verifyNumCerts(t, certs, 0)
}

func verifyNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Error : %q", err)
	}
}

func verifyNumCerts(t *testing.T, certs []*x509.Certificate, num int) {
	if len(certs) != num {
		t.Fatalf("test case should return only %d certificate/s", num)
	}
}
