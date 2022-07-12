package x509

import (
	"crypto/x509"
	"testing"
	"time"
)

// ---------------- Chain Validations ----------------

var rootCertPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICyTCCAbGgAwIBAgIJAMKoxLbsiLVFMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV\n" +
	"BAMMBFJvb3QwIBcNMjIwNjMwMTkyMDAyWhgPMjEyMjA2MDYxOTIwMDJaMA8xDTAL\n" +
	"BgNVBAMMBFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC79rff\n" +
	"wcHY1g4Y3V89m8wmT9O5EuWzv2CXMRNuDHiAEzYtpCCZNXUzK2tDx0SMm7gSbL5R\n" +
	"sygeug1xo6B5ItcpS3Jr65sFd8XO/F2g8PRGZH5eZEBF+dogOjP1QgpkHtAtWuZh\n" +
	"Lc4O9Le6uqLHRm2bFOnyiqSSa/DbXdTXMIabOgVIHHOrDRM+uBYkPqV2PtUnGiNx\n" +
	"mVSatO/Gd8AMJ3QjuGxiArrMGPn5H0NrhaESbioFET2uHx337KNpSXjYOvI4zqbn\n" +
	"/E5XQrXk7WFvrrVytSNvoZKe2C3Rkx++LlMo6mGjnV4LmKptHRGEn+G4BxhFfYSF\n" +
	"cg8i2f/DPUEksEyvAgMBAAGjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0P\n" +
	"AQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQB15AV+zNYU9H6CP4kT15yUaxE1\n" +
	"X1z5vt5K7yC0KTQgEuwouyhjK74FtGb7DRz1Irmncx9Ev109CCWfQIasJw1NaHCC\n" +
	"+TB0y7CVet4nawFTVTt3rJoLm3AAAh5EY0cOxSfF+kBSWQAPzBwK4XeeF10fqZde\n" +
	"r5ArNp1mk1X1GQPWr+bFzuAhOfbyo1rtX3JhTi9aPrH056mIVfnnS/6+jjqOYpeJ\n" +
	"EE2d/AqAytdgXIWq0Y/x/wymXgVINK2NEs1ajRyLPc9uGopZZFKyteqSbIk5H1PM\n" +
	"iVADu+Kjj+JocaQ4vRFSmR+5DGnLdBkP+woioprEIYD42nn7vW0yAZcuLnmo\n" +
	"-----END CERTIFICATE-----"

var intermediateCertPem1 = "-----BEGIN CERTIFICATE-----\n" +
	"MIICyjCCAbKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARSb290\n" +
	"MCAXDTIyMDYzMDE5MjAwM1oYDzMwMjExMDMxMTkyMDAzWjAYMRYwFAYDVQQDDA1J\n" +
	"bnRlcm1lZGlhdGUxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JTs\n" +
	"aiC/7+bho43kMVyHDwCsuocYp4PvYahB59NsKDR4QbrImU5ziaQ94D0DQqthe9pm\n" +
	"qOW0SxN/vSRJAZFELxacrB9hc1y4MjiDYaRSt/LVx7astylBV/QRpmxWSEqp0Avu\n" +
	"6nMJivIa1sD0WIEchizx6jG9BI5ULr9LbJICYvMgDalQR+0JGG+rKWnf1mPZyxEu\n" +
	"9zEh215LCg5K56P3W5kC8fKBXSdSgTqZAvHzp6u78qet9S8gARtOEfS03A/7y7MC\n" +
	"U0Sn2wdQyQdci0PBsR2sTZvUw179Cr93r5aRbb3I6jXgMWHAP2vvIndb9CM9ePyY\n" +
	"yEy4Je7oWVVfMQ3CWQIDAQABoyYwJDASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1Ud\n" +
	"DwEB/wQEAwICBDANBgkqhkiG9w0BAQsFAAOCAQEALR0apUQVbWGmagLUz4Y/bRsl\n" +
	"mY9EJJXCiLuSxVWd3offjZfQTlGkQkCAW9FOQnm7JhEtaaHF1+AEVLo56/Gsd/hk\n" +
	"sXsrBagYGi72jun7QTb6j7iZ3X9zanrP3SjdkpjVnqxRfH83diSh0r68Xruq1NSK\n" +
	"qhUy1V+KQaXF0SSEutPqdTCoXUyxyXohVLU78uqZX/jx9Nc1XDuW9AZd+hMsLdk8\n" +
	"qGJqHYFvj2vOHGMTeYk8dWgMBthQeL0wdsg2AvKtAvn6FQXCN7mKCWjpFTtYsU8v\n" +
	"NsesS9M/i+geJjR/8/DDT3RP7S100BtCMm4XfHfmKcjXVaBh5evQVqGsa6TKLw==\n" +
	"-----END CERTIFICATE-----"

var intermediateCertPem2 = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC0zCCAbugAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1JbnRl\n" +
	"cm1lZGlhdGUxMCAXDTIyMDYzMDE5MjAwM1oYDzMwMjExMDMxMTkyMDAzWjAYMRYw\n" +
	"FAYDVQQDDA1JbnRlcm1lZGlhdGUyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
	"CgKCAQEAxH57OcIDpmuHgZ3y78HpyfNHVy0JwIpIp1quSBN5SHRkzouh+LcuVjic\n" +
	"/1DGwiut312XeIyKoeOLcNnsY1qfZgxtFxJCfZSArnyoHb6O0vRvUq/yY1cjOZea\n" +
	"J4U/ZsSPEt4S5oFApWLGFH6c7sRNmh3bPcPDsm1gNd+gM/UCSyCH62gmRn3r5nKA\n" +
	"4fkwrs46tBGDs+bwwj5/AupJETX4P+NaFE7XcAJP6ShMAGa/ykunyEvDsc8tdzhD\n" +
	"zvoyWRxMjrTZlAu+5THbz4ZgRZja2noQDGoV5g9QMzebLbAS/+YY+OJfGHtA0li8\n" +
	"THw5ZzButCmk+Us49FlN0MlyDC4oNwIDAQABoyYwJDASBgNVHRMBAf8ECDAGAQH/\n" +
	"AgEAMA4GA1UdDwEB/wQEAwICBDANBgkqhkiG9w0BAQsFAAOCAQEADbd56yUDfUCQ\n" +
	"pahXOS0OYBJ9GB+PRdp6lkvZTNPfu5cynZwla1juZFee71w+fcppSzpecGu8esLO\n" +
	"h9+1RooWKGqJpLoAvvUJMW6kZsGBTPjpSeH6xUP9HwxfWrZwg3FMMGMIzOs90jCZ\n" +
	"47U6CevxAGTtkvO8QMIQOx9VNcUDjX1utlkyCdAHccZLq2gw9wWHSfZWydKXpJVP\n" +
	"ffDPsF4LkjJb7XHFB8KOxYjvyomLXGTNlni1hRxadSKrRX9xeAztIZ1ReFgYVRQn\n" +
	"8TwCIeaN4N2TNJWeVmBSnYU7iuay6A/qkauuG2+Hc7eL834IzRejYpecoCjBwQFT\n" +
	"6OInMQCKnA==\n" +
	"-----END CERTIFICATE-----"

var codeSigningLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC5DCCAcygAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1JbnRl\n" +
	"cm1lZGlhdGUyMCAXDTIyMDYzMDE5MjAwM1oYDzMwMjExMDMxMTkyMDAzWjAaMRgw\n" +
	"FgYDVQQDDA9Db2RlU2lnbmluZ0xlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
	"ggEKAoIBAQCfySlwm2lF1eMP8RZVjG1PAp6wJiqNfI1m4Oll5jZFBDPLFqUJFG2i\n" +
	"Zun5GecxJD8mz56AxB95vohQd1+AkPXE7bCpN085hQm3jMbbdg0N0HS+cAATGUDR\n" +
	"VEi/laHLSs8myuG9enJ1/EIGli8hZnOeSW46RaHtlawPbIXa8/8yV1McmrQjOOqj\n" +
	"K+m1Rra2J3apyqUL37K6MrydoLIy/ldvuGbfMDrsRZVu6GbtNMyV+6qwc91NL0aa\n" +
	"g67ge3LaQ4VcLXFSCYpbNzBMl+xBYGLFS4EgNe3VT0HOfOwYn7hcwRF7I0jmUBgH\n" +
	"BTP2yGYKuobDMslaK+FHisptT/qn29ihAgMBAAGjNTAzMA4GA1UdDwEB/wQEAwIH\n" +
	"gDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEB\n" +
	"CwUAA4IBAQB8BAQTnqDkm4K4l0W6a26gl+usPmKzOsrFuKCbeAjUuNMOEcnignO0\n" +
	"URPXvXBEbQGMyNNmS7ix7JjU4BqbM4KSFfIXrCWvdHZTicWl+1+84HVktwmW2bIg\n" +
	"xJPo+m1ZLAsRLnBFmf27p7QBYVCYUvNKvbAqgP9rOPtTOkHe2WtiVNAGxDvWBdKr\n" +
	"gHcqUwRA3v7VfmW9EDoxLvkI9R0HolbiYQzp7GmA+KT5L/CMd50+2fUGaUnaacrU\n" +
	"v8kypIYx5OTOGTYisidXueUhhbp6RZYvpiQuX+O/bkIjSPMf+oXgbDcpRe18XeK4\n" +
	"cwtsQn/iENuvFcfRHcFhvRjEFrIP+Ugx\n" +
	"-----END CERTIFICATE-----"

var timeStampingLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC5TCCAc2gAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1JbnRl\n" +
	"cm1lZGlhdGUyMCAXDTIyMDYzMDE5MjAwNFoYDzMwMjExMDMxMTkyMDA0WjAbMRkw\n" +
	"FwYDVQQDDBBUaW1lU3RhbXBpbmdMZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
	"MIIBCgKCAQEAyx2ispY5C5sQCiLAuCUTp4wv+fpgHwzE4an8eqi+Jrm0tEabTdzP\n" +
	"IdZFRYPZbgRx+D9DKeN76f+rt51G9gOX77fYWyIXgnVL4UAYNlQj58hqZ0IO22vT\n" +
	"nIFiDbJoSPuamQaLZNuluiirUwJv1uqSQiEnWHC4LhKwNOo4UHH5S3XkkYRpdFBF\n" +
	"Tm4uOTaQJA9dfCh+0wbe7ZlEjDiuk1GTSQu69EPIl4IK7aEWqdvk2z1Pg4YkgJZX\n" +
	"mWzkECNayUiBeHj7lL5ZnyZeki2l77WzXe/j5dgQ9E2+63hfBew+O/XeS/Tm/TyQ\n" +
	"0P8bQre6vbn9820Cpyg82fd1+5bwYedwVwIDAQABozUwMzAOBgNVHQ8BAf8EBAMC\n" +
	"B4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0B\n" +
	"AQsFAAOCAQEAB9Z80K17p4J3VCqVcKyhgkzzYPoKiBWFThVwxS2+TKY0x4zezSAT\n" +
	"69Nmf7NkVH4XyvCEUfgdWYst4t41rH3b5MTMOc5/nPeMccDWT0eZRivodF5hFWZd\n" +
	"2QSFiMHmfUhnglY0ocLbfKeI/QoSGiPyBWO0SK6qOszRi14lP0TpgvgNDtMY/Jj5\n" +
	"AyINT6o0tyYJvYE23/7ysT3U6pq50M4vOZiSuRys83As/qvlDIDKe8OVlDt6xRvr\n" +
	"fqdMFWSk6Iay2OCfYcjUbTutMzSI7dvhDivn5FKnNA6M7QD1lqb7V9fymgrQTsth\n" +
	"We9tUxypXgMjYN74QEHYxEAIfNOTeBppWw==\n" +
	"-----END CERTIFICATE-----"

var unrelatedCertPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC6jCCAdKgAwIBAgIJAJOlT2AUbsZiMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAzMTcyM1oYDzIxMjIwNjAxMDMxNzIzWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOZe\n" +
	"9zjKWNlFD/HGrkaAI9mh9Fw1gF8S2tphQD/aPd9IS4HJJEQRkKz5oeHj2g1Y6TEk\n" +
	"plODrKlnoLe+ZFNFFD4xMVV55aQSJDTljCLPwIZt2VewlaAhIImYihOJvJFST1zW\n" +
	"K2NW4eLxt0awbE/YzL6beH4A6UsrcXcnN0KKiu6YD1/d5TezJoTQBMo6fboltuce\n" +
	"P/+RMxyqpvip7nyFF3Yrmhumb7DKJrmSfSjdziI5QoUqzqVgqJ8pXMRb3ZOKb499\n" +
	"d9RRxGkox93iOdSSlaP3FEl8VK9KqnD+MNhjVZbeYTfjm9UVdp91VLP1E/yfMXz+\n" +
	"fZhYkublK6v3GWSEcb0CAwEAAaNFMEMwDgYDVR0PAQH/BAQDAgeAMDEGA1UdJQQq\n" +
	"MCgGCCsGAQUFBwMIBggrBgEFBQcDAQYIKwYBBQUHAwQGCCsGAQUFBwMIMA0GCSqG\n" +
	"SIb3DQEBCwUAA4IBAQCaQZ+ws93F1azT6SKBYvBRBCj07+2DtNI83Q53GxrVy2vU\n" +
	"rP1ULX7beY87amy6kQcqnQ0QSaoLK+CDL88pPxR2PBzCauz70rMRY8O/KrrLcfwd\n" +
	"D5HM9DcbneqXQyfh0ZQpt0wK5wux0MFh2sAEv76jgYBMHq2zc+19skAW/oBtTUty\n" +
	"i/IdOVeO589KXwJzEJmKiswN9zKo9KGgAlKS05zohjv40AOCAs+8Q2lOJjRMq4Ji\n" +
	"z21qor5e/5+NnGY+2p4A7PbN+QnDdRC3y16dESRN50o5x6CwUWQO74+uRjrAWYCm\n" +
	"f/Y7qdOf5zZbY21n8KnLcFOsKhwv4t40Y/LQqN/L\n" +
	"-----END CERTIFICATE-----"

var intermediateCertInvalidPathLenPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC1TCCAb2gAwIBAgIBATANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1JbnRl\n" +
	"cm1lZGlhdGUyMCAXDTIyMDYzMDIwMDY0OVoYDzMwMjExMDMxMjAwNjQ5WjAaMRgw\n" +
	"FgYDVQQDDA9BbHRJbnRlcm1lZGlhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
	"ggEKAoIBAQDDyujPemQdVtV5yoWk334MPwaj8kFcquvcNTQXX/Jx5F7IZD6E0E7F\n" +
	"2bgGdwxAwzhrZni+aMJtyT0YX9Kgi0Tm+86hBdN0gfNcQojr3qdB2CUnAwaNStn+\n" +
	"DaF5kw+Pg6WQE8k9yYMkavmbdegyvzSComtksyUYDtU6V/eBuHIIFviDrK0lrbhs\n" +
	"VTtuA0OWoUq3uv+TMEFKpak/XQ9vgor1CKORS16r/OgPTPpHzVibw/gjrwh5Ex1g\n" +
	"cNcsing92AMJxeT1UqOK6luVOwXmSD5Ixn8Ls2wWtgUtlszyA1E+5UHyfwbz6cdC\n" +
	"H4vdRJsFa8dEaA/+H50iHVslakL86YRrAgMBAAGjJjAkMBIGA1UdEwEB/wQIMAYB\n" +
	"Af8CAQAwDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQBVZ8oMemPX\n" +
	"CegjTJJ302qmW1PlwkQ6w0CSIaw9lXbG8g8IsDCh/PJCJFwZN0LcW/wjPmMHWulS\n" +
	"xblyIQbUM6Y7jS7/YmmvHW2A7SiANHSGHKb0AwsAZRbuoOXYxyr0D3QIIktf65xC\n" +
	"qRpkoTuKpPdEer8wTvq1SN4B/4/VbdeIk7RFw2XAADnMDbcsqvU2O3SX+zl4yHev\n" +
	"vsoj63SWGIH4Sk8TUBo/s3WyuSWMEUs/wW71w9Yeo57K8+X/hTaC2GEUtcsdPSGL\n" +
	"E31rl9wvwouARTBAopy3ocw+hEwuwMIH8mhf5qih8TIwG10yV1tR2kgmvhgGICQN\n" +
	"dhS0BR1O8DCe\n" +
	"-----END CERTIFICATE-----"

var codeSigningLeafInvalidPathLenPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC6TCCAdGgAwIBAgIBATANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9BbHRJ\n" +
	"bnRlcm1lZGlhdGUwIBcNMjIwNjMwMjAwNjUwWhgPMzAyMTEwMzEyMDA2NTBaMB0x\n" +
	"GzAZBgNVBAMMEkFsdENvZGVTaWduaW5nTGVhZjCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
	"ggEPADCCAQoCggEBAPAi9EWIguIIxXSIcJpU0+LZoKjB2ZGPJJOoY+0jzlMRdCLy\n" +
	"olU4Frmnke5+cVyTdHB/2f26eKZJe5iNCZi0EYjUUzuumnhDPvUxXkt1Qz46CGyE\n" +
	"X0oc0pfNz/jtCbK4gR8sm6qp5S/wXcrKStN06MKYbPARRdKuS4kQklylwDcyAXo6\n" +
	"Se47EdqLP+Vav8++Oj/L0fQbDs06s+N+mChgZA4VVClgxQkrslqM7wasJS2wLe1N\n" +
	"VFL3oDbmtAei+sV5PmLaesjb6LXi4VNu3MPMHbR3h3WzG19S590Ob81TlhvIcciH\n" +
	"FsWWU8PdKx1KWlwpht718r6Fzi+lS81bCwWtMEkCAwEAAaM1MDMwDgYDVR0PAQH/\n" +
	"BAQDAgeAMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDQYJKoZI\n" +
	"hvcNAQELBQADggEBAJ73158p7+5OIo5JNK7gW2e7EM/2659tuaKZ3HWTzkDrgw9O\n" +
	"YKQhpl1QizFCAgps/DTy+nBzrt5o4Rl9jUPKSvfAWGOGhb2MYNre9szKARhVg3ij\n" +
	"rGhhUtlpCUAHBZRdKUvXkBGbp+FTjZuYdsN1HBXJ5aZkwVi7P9JQjTn406DOoPgy\n" +
	"Fr4upDTYzskjFIF2tMwCkfy9Mc2KAV20wtGnr6j2PIqrhwE3DClMptUS5KfL0wp5\n" +
	"HasYvDIttHtgGR8lFTda4KvldG2u0t7E8glAb/n2oNQ1tsDojR/9Njnp+ZmmrJNi\n" +
	"L0Z9ZU3NwwFAh1wpSsoQR4pPN+ZkVj5Irr/KWFk=\n" +
	"-----END CERTIFICATE-----"

var rootCert = parseCertificateFromString(rootCertPem)
var intermediateCert1 = parseCertificateFromString(intermediateCertPem1)
var intermediateCert2 = parseCertificateFromString(intermediateCertPem2)
var codeSigningCert = parseCertificateFromString(codeSigningLeafPem)
var timeStampingCert = parseCertificateFromString(timeStampingLeafPem)
var unrelatedCert = parseCertificateFromString(unrelatedCertPem)
var intermediateCertInvalidPathLen = parseCertificateFromString(intermediateCertInvalidPathLenPem)
var codeSigningLeafInvalidPathLen = parseCertificateFromString(codeSigningLeafInvalidPathLenPem)

var signingTime = time.Now()

func TestValidCodeSigningChain(t *testing.T) {
	certChain := []*x509.Certificate{codeSigningCert, intermediateCert2, intermediateCert1, rootCert}

	if err := ValidateCodeSigningCertChain(certChain, signingTime); err != nil {
		t.Fatal(err)
	}
}

func TestValidTimeStampingChain(t *testing.T) {
	certChain := []*x509.Certificate{timeStampingCert, intermediateCert2, intermediateCert1, rootCert}

	if err := ValidateTimeStampingCertChain(certChain, signingTime); err != nil {
		t.Fatal(err)
	}
}

func TestFailEmptyChain(t *testing.T) {
	certChain := []*x509.Certificate{codeSigningCert}

	err := ValidateCodeSigningCertChain(certChain, signingTime)
	assertErrorEqual("certificate chain must contain at least two certificates: a root and a leaf certificate", err, t)
}

func TestFailInvalidSigningTime(t *testing.T) {
	certChain := []*x509.Certificate{codeSigningCert, intermediateCert2, intermediateCert1, rootCert}

	err := ValidateCodeSigningCertChain(certChain, time.Unix(1625690922, 0))
	assertErrorEqual("certificate with subject \"CN=CodeSigningLeaf\" was not valid at signing time of 2021-07-07 20:48:42 +0000 UTC", err, t)
}

func TestFailChainNotEndingInRoot(t *testing.T) {
	certChain := []*x509.Certificate{codeSigningCert, intermediateCert2, intermediateCert1}

	err := ValidateCodeSigningCertChain(certChain, signingTime)
	assertErrorEqual("certificate chain must end with a root certificate (root certificates are self-signed)", err, t)
}

func TestFailChainNotOrdered(t *testing.T) {
	certChain := []*x509.Certificate{codeSigningCert, intermediateCert1, intermediateCert2, rootCert}

	err := ValidateCodeSigningCertChain(certChain, signingTime)
	assertErrorEqual("certificate with subject \"CN=CodeSigningLeaf\" is not issued by \"CN=Intermediate1\"", err, t)
}

func TestFailChainWithUnrelatedCert(t *testing.T) {
	certChain := []*x509.Certificate{codeSigningCert, unrelatedCert, intermediateCert1, rootCert}

	err := ValidateCodeSigningCertChain(certChain, signingTime)
	assertErrorEqual("certificate with subject \"CN=CodeSigningLeaf\" is not issued by \"CN=Hello\"", err, t)
}

func TestFailChainWithDuplicateRepeatedRoots(t *testing.T) {
	certChain := []*x509.Certificate{rootCert, rootCert, rootCert}

	err := ValidateCodeSigningCertChain(certChain, signingTime)
	assertErrorEqual("certificate chain must not contain self-signed intermediate certificates", err, t)
}

func TestFailInvalidPathLen(t *testing.T) {
	certChain := []*x509.Certificate{codeSigningLeafInvalidPathLen, intermediateCertInvalidPathLen, intermediateCert2, intermediateCert1, rootCert}

	err := ValidateCodeSigningCertChain(certChain, signingTime)
	assertErrorEqual("certificate with subject \"CN=Intermediate2\": expected path length of 1 but certificate has path length 0 instead", err, t)
}

func TestRootCertIdentified(t *testing.T) {
	if isSelfSigned(codeSigningCert) || isSelfSigned(intermediateCert1) ||
		isSelfSigned(intermediateCert2) || !isSelfSigned(rootCert) {
		t.Fatal("Root cert was not correctly identified")
	}
}

// ---------------- CA Validations ----------------

func TestValidCa(t *testing.T) {
	if err := validateCACertificate(rootCert, 2); err != nil {
		t.Fatal(err)
	}
}

func TestFailInvalidPathLenCa(t *testing.T) {
	err := validateCACertificate(rootCert, 3)
	assertErrorEqual("certificate with subject \"CN=Root\": expected path length of 3 but certificate has path length 2 instead", err, t)
}

var noBasicConstraintsCaPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICtzCCAZ+gAwIBAgIJAOhRHhdRoeaNMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAxMzAxNVoYDzIxMjIwNjAxMDEzMDE1WjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN3s\n" +
	"ujhpbbJgOmy3bPdnE0JSSH/i3+TwwR0+/g2qTt3cOHC/X59/w03julru5HQYSUqG\n" +
	"Q4OlngVb2WoujuVPWwyYjP8nuhSUnWl6vhI8zrO300dhLtJvSa62bKOcmtseeWCo\n" +
	"KerJXHYqYWl+2nSyVI6x3yuXnJOnS68YAaZ69nqRgu8Cym/144DatzmY2TGuz7bm\n" +
	"TyP4CDWuUulxIOdp6GZg2raIRi//SJcA1UFjBx0n7H8XUcKV2xAO4e8xSK9KTMEm\n" +
	"QRA9H2pyT1QDaMeewbzhMEdWDwDnmkZPaWOXIIQ+x1eSvlr/6cQSIaBGKMkUMkq4\n" +
	"qX98M1dtth0BrhK22jkCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3\n" +
	"DQEBCwUAA4IBAQCyYgO+VA0+6VPz4cndEIsE1NZSFQwxNcKzC4esGivyBIadoH7U\n" +
	"lNMKw01UUpRUcIiehVCL11FGwMsJ08sDdMB7i/2UwCwodyT/6/6oFm08nUaiC/nV\n" +
	"ryMcDwyregNLSbK7GgHNidSBSXnFmvFAkUSvIUvoulGtH9B8MkdU3SmT7VFf9WQ1\n" +
	"lrh/nTAnUlTh48Mn4zpf96VLIw2d42Oq96pYYZy6k+/2h2zph9CuwBvK5cJjDLY3\n" +
	"3BCBV/ffCxM0v2mclr/CMXNvxVbtgGnQJVjoaccLRXS7C7+CbrP/bimszyyMRGcs\n" +
	"WkOh2T0tPw9Fr1zsyFzLeJ9A9zEr8tVW0qi3\n" +
	"-----END CERTIFICATE-----"
var noBasicConstraintsCa = parseCertificateFromString(noBasicConstraintsCaPem)

func TestFailNoBasicConstraintsCa(t *testing.T) {
	err := validateCACertificate(noBasicConstraintsCa, 3)
	assertErrorEqual("certificate with subject \"CN=Hello\": ca field in basic constraints must be present, critical, and set to true", err, t)
}

var basicConstraintsNotCaPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICyDCCAbCgAwIBAgIJAJcTAoRqhzWEMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAxMzMwNloYDzIxMjIwNjAxMDEzMzA2WjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKIk\n" +
	"nuaT8Ho7UM9kYJVWWEINS51/glLHj0Zqdu+Qa4gbzd3FjQBfjpyilJBDm7bhuxHu\n" +
	"UOeqPnn9QXAX9WLiR6NPXeaMuWG/D98gJ8+jMmOc+Xw6Nicc8w3rHFz3ZscOuCII\n" +
	"zcXLjh+GhW+1uwwOGalnud1yXs17gP1cYT3qSMIfsrNrCLMZfvmvI0LGYEAuLJLB\n" +
	"OhYiP0jq10vXAEsiwHKC24PGM3u+kQ35CsAEvUFlSLoKx0qkYvhfBsGfoisTXTJt\n" +
	"5kdnmxB1z0qCYvsub7/pID7WjnD2dFGfkEjF34wTM8Re6wrHl7ibk4Y3ojCurfVv\n" +
	"/LTp3QZuiS79zla7pGkCAwEAAaMjMCEwDwYDVR0TAQH/BAUwAwIBAzAOBgNVHQ8B\n" +
	"Af8EBAMCAgQwDQYJKoZIhvcNAQELBQADggEBAEJA6l1vPSnnpyONee2yAcN8nYR8\n" +
	"wMgv4KNfGKzD3ZBPofoFxN+rSbB6KyeRp9x5ot3vxfVTWuayMssga/BKQl9+Lbp2\n" +
	"Q2QMpGVgbCrJ3EQO7kADJroChncKs05nDTeZW84mwurkoQXKWlM7JVYgfnKfCpA9\n" +
	"CaK9Eeeyxpo2Hjgix1y5ml4L35+LUgP3yNZWE3RzyGAb28pgy0SqViBD9UQYa5xa\n" +
	"hPVr+C/Ukfl2UCzG6DW4kHNHyY1W0C7eYVN+YQiTlqzvqc7qkRsfq1cqVPEYKmzF\n" +
	"UMrDhmmzAhKOOW+MxCwWtwHt5m/6eUyal9L27jRdC9tfOfgyMp7kdzSQ/pI=\n" +
	"-----END CERTIFICATE-----"
var basicConstraintsNotCa = parseCertificateFromString(basicConstraintsNotCaPem)

func TestFailBasicConstraintsNotCa(t *testing.T) {
	err := validateCACertificate(basicConstraintsNotCa, 3)
	assertErrorEqual("certificate with subject \"CN=Hello\": ca field in basic constraints must be present, critical, and set to true", err, t)
}

var kuNotCriticalCertSignCaPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICyDCCAbCgAwIBAgIJAKo2P71SNRaxMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAxNDAwMVoYDzIxMjIwNjAxMDE0MDAxWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKsB\n" +
	"y9q80Va4LFIC1WzpfFLQnf2KqjSeJY9ELooMoZHdLDDr9tDKag58FyNJHQCM+9rF\n" +
	"TOArmxj97e2Eyppild2GhB/0RmqycvSo4ecrjDausTQIU6hpyvWJ27f2L9xnr0By\n" +
	"lDXBkDPiN+idYRmMRNGS2nnK6qtAPqhAix1SAZbu7Pn2uKYVjXgy1I5oJPA0bT66\n" +
	"nLfEynU8wxodXC8tR0+wsuRw+M0hRaPDtzq7JccOqSgokyfZwfWr7JmOQNqk6MQc\n" +
	"STbE6VrqOo8A1c4BL2V4Cqb7G7ixrcyeJkmExyJO1ENdDl5B1rKaeDggRLBSlXbe\n" +
	"lHz2lFexghYSModdsoMCAwEAAaMjMCEwEgYDVR0TAQH/BAgwBgEB/wIBAzALBgNV\n" +
	"HQ8EBAMCAgQwDQYJKoZIhvcNAQELBQADggEBAEA721CsrPbMQOJ57QsnhCrXl1V4\n" +
	"A9gg5+EDIqhp1V9Gv110THm1wonm3XnBGZ7vT1fmbgbfWpW5e/o1hreDOzHT+qnl\n" +
	"QAqEe9Ff7CuVwgoswordb+Z8bO63RhC3Vy4wsb6TjN8Mwzt62HT99eZQV4HABD9r\n" +
	"Ov5J38UIzsgjFiQ38WqOh5f1lc5XIajeLEln0Rb7gifuvCQ5rr72VPLNtRckOuRl\n" +
	"Bf0yN3aS5Sf7ulQwrCeDWgKYNh1nDfgX+wd4iDId3DGeT3aeR6wJ2t6jooKuuMpc\n" +
	"VaowNWN3SqUXWBLEROLhse6UiHAZprWkvAHVg/Ak2SOLx2T+LHPah7pSceM=\n" +
	"-----END CERTIFICATE-----"
var kuNotCriticalCertSignCa = parseCertificateFromString(kuNotCriticalCertSignCaPem)

func TestFailKuNotCriticalCertSignCa(t *testing.T) {
	err := validateCACertificate(kuNotCriticalCertSignCa, 3)
	assertErrorEqual("certificate with subject \"CN=Hello\": key usage extension must be marked critical", err, t)
}

var kuMissingCaPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICuzCCAaOgAwIBAgIJAIeB8Anz7VXqMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAxNDM0OVoYDzIxMjIwNjAxMDE0MzQ5WjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKC3\n" +
	"3zL1jb7Htbom426qrZLNhBAjp4wmcMnj8zk19Yc4C6+pYmjxzQWvJlh1gRvMuCwv\n" +
	"TGA2WGn2IPJNwWWt2DkL2dxA30dzBUr2shLVnlMd0GkMthjRGqqU+ELPlCio3yC8\n" +
	"fBoUMWkH2AoDXPUJgAtT8ASmyRfcOnLUXMOreXgpQo4BjDt1i9QQGx6epqn4lvCH\n" +
	"3ptE6mmBcrVxRxmXuHFu9/IrHs98+EeRKHMwASwqf7+l2+pX+hQ4VjxOERJWX2Qt\n" +
	"8iTBS9eLGj72DVzMUKIvG/Br5HKTY/BDEsnWv53rtyZMs6tuLFmOmSTGJSfF3DgJ\n" +
	"EohedhICOga+t6Fkpm8CAwEAAaMWMBQwEgYDVR0TAQH/BAgwBgEB/wIBAzANBgkq\n" +
	"hkiG9w0BAQsFAAOCAQEAL41qG7xOJbwCV/Z7SqFOlCq1t7p4M0ZslQ8zuZ52VTUO\n" +
	"u+7Uzb6fcxfLZDeWYEUcjbTB4TpJexQBQoR1To/yWarNmcDc9Zar/+sggq+peO3m\n" +
	"vCp/hJRjGFnAy9FTCu0+BOCcT4gnTW8j6qXxek6+DuqPUuL93FH0tjteU4zdIf4/\n" +
	"/Kqq9FkbLJQ6wVDxfwA2Z/okhLhC4kCH6FHmeOVxguUktaq1qzOWiwCcvC/+/4VW\n" +
	"sKcKXaTkPwsDSoP7I0+YpUwhl5inLWhhiB2O8fG1D8EHDRZaZr/I7KDaQyYkX5VL\n" +
	"/8Qa6becfIs3wZKg+zDadgH6yFOFrR3bxK8RvWWw8w==\n" +
	"-----END CERTIFICATE-----"
var kuMissingCa = parseCertificateFromString(kuMissingCaPem)

func TestFailKuMissingCa(t *testing.T) {
	err := validateCACertificate(kuMissingCa, 3)
	assertErrorEqual("certificate with subject \"CN=Hello\": key usage extension must be present", err, t)
}

var kuNotCertSignCaPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICyzCCAbOgAwIBAgIJALaWmRd5mz8WMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAxNDIzMVoYDzIxMjIwNjAxMDE0MjMxWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJV1\n" +
	"Q8p/3spuT83/eXuEXT4G2bVQqho48ctbbSIAcW0x1q85XL+jAXlP+nynodUAaKif\n" +
	"W8hMx/ccqvBl8tlVTe4Dk25aSbUWQKJ+uMEKRyQdexj3WR6+QMxAbx4QB5rwGG9D\n" +
	"qLLXhio9u1Gsau5zN3oFlX89s0e+wk68XOh//LQEgmnSzgd/HHj8w3YQSJRzyQ0q\n" +
	"MzAhiSvdofnrOWL7JBj7xs+3MoYfnt3fNRLxxJYIJO8ap3CkWUVCRw/u/YTJu1QT\n" +
	"BwfWrLTdT0YykH2Ok7nK1FmBEyNgsfyeGhq2P5RDRO9nL/2WkcZw1RTvIvBC8fvb\n" +
	"8W8pVj++VKDeJBc5q/MCAwEAAaMmMCQwEgYDVR0TAQH/BAgwBgEB/wIBAzAOBgNV\n" +
	"HQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBAEEugs5u/lOxRHbg/qspyYkb\n" +
	"kcCuZsW6cpnKtEJED+dsBnswvG+LtIBlOazBzbPDbR78DbNWgYxTBkb/+40XIfFs\n" +
	"H8BTRXd3zMjrxELMjaHMzwCvec9BzIOiCz0eqYVJXKK8h/YhyCIy0F+GvrYOXTkp\n" +
	"llENwqKs26M2H4CScEpoMu0VsBnFNSNj1epV/Bs+sfIPcUY7EB0dMGURM+7vQ/uv\n" +
	"sotc3rHQCGFxArMpJ75nbWR53WtTm/l7p1RHVsKXb304nKT1bFc7xRnicDhjT4Ps\n" +
	"SZSlZJ3hMRHo1IyeSkjzCICEsfzmXozlIKkEpmcHxHkoT6+zazrdM4CH5DySGkk=\n" +
	"-----END CERTIFICATE-----"
var kuNotCertSignCa = parseCertificateFromString(kuNotCertSignCaPem)

func TestFailKuNotCertSignCa(t *testing.T) {
	err := validateCACertificate(kuNotCertSignCa, 3)
	assertErrorEqual("certificate with subject \"CN=Hello\": key usage must have the bit positions for key cert sign set", err, t)
}

// ---------------- Code-Signing + Time-Stamping Leaf Validations ----------------

var validNoOptionsLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICtzCCAZ+gAwIBAgIJAL+FUPhO8J8cMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAxNTMzMloYDzIxMjIwNjAxMDE1MzMyWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALrP\n" +
	"tWr9wlTWsaZhliJbe+IWNwd+GRfQ/RDqkE8VLd/JmU5HTWzIHQ6Rb1Pkw7Ugp1vQ\n" +
	"xo8OcwN8w774QqdzoWgwtasnLsuLanyyyVacSByRz+VTeRKv2StMV/bezNnhcJ6T\n" +
	"7cj6dVrkIjf7ViCs9om0P724lvfEW+toMgbHMDyJ16Rwi2Q3OuHKvWrP7BL2l/0X\n" +
	"E35ZuE+gUdIOgVyoBnk56LIP1VtUtwE5Q9zO/cM+5vHbUj2xtmnLOkFmZGR+w15F\n" +
	"mG85PHR6aYRh7wr3tjd78eFYlvwdK9BfxCZlkHs5LmFEXt1g/I0C62xSjTKWQSi8\n" +
	"aa6+55MGgU+UVjh+6jkCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3\n" +
	"DQEBCwUAA4IBAQCtK8xTIK4lR6Po5p3BraeV8LDNCHKDRkHtYQfnqYxqaqGcNG36\n" +
	"6Bsp37cVS8Md6pRdMwCXizqJvu782iWk2oyQTf05TW4CW0doEzFLIO+HJk0+dVNg\n" +
	"+mUbXjWlRxA9PQS2NVzkBwKGnN2b7yNT70jA6CU+LHRJaGFYr2zLny4fhsViG8P4\n" +
	"0TtU6Zy0EPJ0k77iGd7TEazSyOyIaEjemKlQjrWYa6VRRCpp6iECwJLHekfvxXy5\n" +
	"pe1tg2DS30BrPdFe2v0lUWf7JkOAqy0Q7dfmUOgN7Oyjtgn3oC7lqpV4wBCRI9wq\n" +
	"DXnpXe7StmJYV3TPc7NX8gAuQHw+GfWnVmZr\n" +
	"-----END CERTIFICATE-----"
var validNoOptionsLeaf = parseCertificateFromString(validNoOptionsLeafPem)

func TestValidNoOptionsLeaf(t *testing.T) {
	if err := validateLeafCertificate(validNoOptionsLeaf, x509.ExtKeyUsageCodeSigning); err != nil {
		t.Fatal(err)
	}
}

var caTrueLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICyDCCAbCgAwIBAgIJAI/1c9qHTFkvMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAyMDQyNloYDzIxMjIwNjAxMDIwNDI2WjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMYF\n" +
	"Cw41ani7Dm9PY8m5IZZ6JbbATeANXA1DKKRqzt1jjvtCn7ya0Ll3Sw3HK6nqUoZz\n" +
	"3hrFPE4rIb84YzCRFs+uEWqFB4VnikyKrJsznfGsw3zQAZw3o2w0pIERDAIWZJlN\n" +
	"wLvFRoI5coRQcAi2DcNXiujssNp4O05ez3IxmCnnOCF6WD87ivB4lIpX/okYsC6g\n" +
	"wLWFiaA/aC5gyPHLXs6B3Vr8yl8Zd/QuOe7ZznTI4E0zObMCk7pCrvzPQjSOE8lE\n" +
	"XaVHs9pGu+Q3ePKw99MhU9zOzkCjwiFxyhMZLTTuLEfdShxJUWtkBjPeRfrFNuRV\n" +
	"v6UKVeQDjWeAF+V5LXMCAwEAAaMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n" +
	"Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggEBACWjhZ6QwVseXcEOwCBMssCkkpiW\n" +
	"Xql/TKQH3b1FWE2FrDmV88J21nRRbtJECNlzkolkk5fHot08S3JBosIjiCaK3MHT\n" +
	"5o2WKOlUvYSUAbCzAIz69cbGCcOAXHKfyO7wP84HUbaFRKSX7xElKS06d6kxw/2R\n" +
	"iMfMobcjf2mlg4SAcUqbWptfDUdV+RfW4qLyqeM1FZCKmYRWAb9bJ2diS0QwU7Rz\n" +
	"XODxVkB4y9BXfh0TtKTvxaRYs/W1V4nyD3DBJDZ6UZKa59zXfPS+Das+d24GfEvz\n" +
	"4dtOHTXGn+s5KE1tmn2cpwZ/megX9mH3FEDNMsFgS00Jp1PmTRiDMZvWLFc=\n" +
	"-----END CERTIFICATE-----"
var caTrueLeaf = parseCertificateFromString(caTrueLeafPem)

func TestFailCaTrueLeaf(t *testing.T) {
	err := validateLeafCertificate(caTrueLeaf, x509.ExtKeyUsageCodeSigning)
	assertErrorEqual("certificate with subject \"CN=Hello\": if the basic constraints extension is present, the ca field must be set to false", err, t)
}

var kuNoDigitalSignatureLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICtzCCAZ+gAwIBAgIJAPcOgGijs80IMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAyMDg1OFoYDzIxMjIwNjAxMDIwODU4WjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKFu\n" +
	"0MuGPCD19KP29Kt1wbQ3d/YgYnVkRJL+HyzZMkcSISr+wBOeH5exsZBttWZLpjPK\n" +
	"cnMNf/anbzAYUxzYPys7LWu4XcfRIdI2HWsz+cGuHqDe8kIzmUv/EOxir34QFRXK\n" +
	"2zVzf8cxIQgh880q1nQG86GU7sObbuF2AnAUZr+ZDZ8QgWsoWQIBX7vijxEa94jh\n" +
	"AVobJsQUJxb/P+tqtLghOlsE6X5Ze/2EpMimNqSee13VRjPxaOnTTyUzYYtYPpoC\n" +
	"QdoHN/ia0Gjmhto6ZKPksmTpdsmsqZnhBCC2KGWlPHZ/mv2KNsGCShuDv7p1gJ91\n" +
	"B9qqefonbT4U1V/XzJcCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\n" +
	"DQEBCwUAA4IBAQBWSg+EPKjdoHQ/aEHpQsOeTI3RONEwHO4XnWP3fJa/I75VSKFP\n" +
	"nSRnmzffvnxs8gNpx02K6nLZILjYNjg9VFRkTgRnX24Xn+h3Egv7/3xA9UpwkiJ1\n" +
	"eG7EUZhgA1HaANebfXIvIapSRMcO1NzKsjh5wUVGUWubt9RzBB2T+NFpB0tueDun\n" +
	"xeGn74C10jG1ER5ne1AjSuCTQvPTrBgw2uClQYxiU70+PS6ZOlfz4oF2sGHzFQCa\n" +
	"3bXCB2iP3UjyImB6lXnEYKpPMUo5yI5yJmABF4b4bJzrMaIvgBS0xxHnLom6/9FD\n" +
	"MJnGuo7eFw1u4lNJRWOpIIYc+8c8HzZsIAjL\n" +
	"-----END CERTIFICATE-----"
var kuNoDigitalSignatureLeaf = parseCertificateFromString(kuNoDigitalSignatureLeafPem)

func TestFailKuNoDigitalSignatureLeaf(t *testing.T) {
	err := validateLeafCertificate(kuNoDigitalSignatureLeaf, x509.ExtKeyUsageCodeSigning)
	assertErrorEqual("certificate with subject \"CN=Hello\": key usage must have the bit positions for digital signature set", err, t)
}

var kuWrongValuesLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICtzCCAZ+gAwIBAgIJAMh6H4wfi2mqMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAyMTEzOVoYDzIxMjIwNjAxMDIxMTM5WjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANyn\n" +
	"YfSfV3AEB9WJmPcoE8LkwfYUKupLeuSTQ92y4biMNCE7RdGhRqLRtr/IkyLKtEal\n" +
	"36cAChinQhYYyi5m+7o6Q2hn+KGYWSI+zC1sylzh2vbmP+xsJpe0RZKdupJThDLg\n" +
	"8pAgtbYF5OhEwK96Xd3fHEmaXfOMCVNV64RiA/qE8mUYPCvCEkzy/9GRqweOYDDb\n" +
	"JuzWdsUEgDqfx/JdzprMzP3h3/qV3XZDNseKugK/ppdEMMnmPlE4wyzyawJdIPIf\n" +
	"otPrurUyxD6pBN2LVeYFJF1nX1Uf+29wjrWTpVSmtDmKQyzb6RYvqtS3LIA+u5bi\n" +
	"lElqTNwCbTGeIGGdnXcCAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3\n" +
	"DQEBCwUAA4IBAQDPypA7akOvbk+mRbEjfiROiNjq7w8eua5EDG86hVVO+zEmQ54a\n" +
	"eNc9nWWwdCAgToiZSu5DExNLAwhZjs/p+6okdRIteaeQCf+6Ur6+XtgeSxQDd1zy\n" +
	"138vrqp+s1tcDGxfZzm5q7sT0U/nTJGEgwGaSketD/gV1pS12So6U1SIIbQ9cDey\n" +
	"c+jiKFj+BPs+WYPGfnj0B/R/Iq5Afsxonot3FlG9vaKZoBJG0KC3vH4Zyir4q6Hs\n" +
	"y0HBHbu0MqIJV0Me2T0IjixlGw1wlqtOHM6lw3qkZzSAdGu6+CPkODwrjur2J87S\n" +
	"rEtF5Jlc3Ea0DGcRTla8FdwZfi9w3TH8i8G0\n" +
	"-----END CERTIFICATE-----"
var kuWrongValuesLeaf = parseCertificateFromString(kuWrongValuesLeafPem)

func TestFailKuWrongValuesLeaf(t *testing.T) {
	err := validateLeafCertificate(kuWrongValuesLeaf, x509.ExtKeyUsageCodeSigning)
	assertErrorEqual("certificate with subject \"CN=Hello\": key usage must not have the bit positions for key cert sign or crl sign set", err, t)
}

var rsaKeyTooSmallLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIBsjCCARugAwIBAgIJAIoMv72RJPnkMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAyMjMzNFoYDzIxMjIwNjAxMDIyMzM0WjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArtSO3a/D\n" +
	"dsI9CA80GtZgNMv1M/p3GWZ/Rvv+WTMT+MShYQ8fAReiyd9oaBVqLIIyusKDjZg6\n" +
	"LQYf3X5L/SLZhAtgCeCzH9/0E+N+ABsP9+DLGuRWct3wAPnI6PlvS6T29CsVIJva\n" +
	"QTuUzMD63Fxci7VzoeMlFLByg6cke8lXKnECAwEAAaMSMBAwDgYDVR0PAQH/BAQD\n" +
	"AgeAMA0GCSqGSIb3DQEBCwUAA4GBAGwNRvIxfbD/yDt0XAMaW6hoMNZ1pEA1fqbF\n" +
	"1Kj3cLNJL3x6JcMYFpoj1lVbF1iv4idIMwsZVnAQO/d3WvlZJEbAQB6J/Bt7zl1T\n" +
	"DamifLxcPW645Re/uWbTC9FrVCwP8Sw6VC3MSMniP3NIHPAQUPrky8Qm4SPYBnTo\n" +
	"rmmUMAVI\n" +
	"-----END CERTIFICATE-----"
var rsaKeyTooSmallLeaf = parseCertificateFromString(rsaKeyTooSmallLeafPem)

func TestFailRsaKeyTooSmallLeaf(t *testing.T) {
	err := validateLeafCertificate(rsaKeyTooSmallLeaf, x509.ExtKeyUsageCodeSigning)
	assertErrorEqual("certificate with subject \"CN=Hello\": rsa public key length must be 2048 bits or higher", err, t)
}

var ecdsaKeyTooSmallLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIBFzCBxqADAgECAgkA9KM1CXSlbcswCgYIKoZIzj0EAwIwEDEOMAwGA1UEAwwF\n" +
	"SGVsbG8wIBcNMjIwNjI1MDI0NzA3WhgPMjEyMjA2MDEwMjQ3MDdaMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE+7pD988OoErMBUx/nRYc\n" +
	"PNOKFf2VJN4rnRHCnbSYZf8gDYo4stt6Ovq19Zzu4vpwZzvgr4cmiFKjEjAQMA4G\n" +
	"A1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNAADA9Ahxf4a+tH/2/hBJ8/XV4yTus\n" +
	"j1G7ww5Ye2f+a02jAh0A6EgSPUhB7UY01gwjwgw7kL+p/hRwr6pHmOmR8g==\n" +
	"-----END CERTIFICATE-----"

var ecdsaKeyTooSmallLeaf = parseCertificateFromString(ecdsaKeyTooSmallLeafPem)

func TestFailEcdsaKeyTooSmallLeaf(t *testing.T) {
	err := validateLeafCertificate(ecdsaKeyTooSmallLeaf, x509.ExtKeyUsageCodeSigning)
	assertErrorEqual("certificate with subject \"CN=Hello\": ecdsa public key length must be 256 bits or higher", err, t)
}

// ---------------- Code-Signing Leaf Validations ----------------

func TestValidFullOptionsCodeLeaf(t *testing.T) {
	if err := validateLeafCertificate(codeSigningCert, x509.ExtKeyUsageCodeSigning); err != nil {
		t.Fatal(err)
	}
}

var ekuWrongValuesCodeLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC6jCCAdKgAwIBAgIJAKZJHdWFNYPlMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAzMDEwM1oYDzIxMjIwNjAxMDMwMTAzWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK2t\n" +
	"EFpNOJkX7B78d9ahTl5MXGWyKIjgfg1PhkYwHKHJWBiqHa1OUewfUG4ouVuaAvJ+\n" +
	"GPzcxt23/J3jK+3/szrzpBNv1f0vgIa+mqaRQDW2m/wfWw3kpcwxlRcL7GnCeHbv\n" +
	"gRFDXQW6MhKgGgKdQ5ezV+p01eF+CzMhUe+bZO+mvgxj36MJHzLMFHyh3x4/+z4x\n" +
	"qRKmj4uUqJ2FJLlQEk92vPE/N3r7rEWa6gd4mBZ+DsZSrCbVPXchS2mCkeg70qxA\n" +
	"4840qVLZ5eFxtqnTEUNytu3ug/8ydV9VmuT+C5fQYUp3Fl7D1QxHxWYTVTKdenCY\n" +
	"jxcJHW1cUWZQlgPTLq8CAwEAAaNFMEMwDgYDVR0PAQH/BAQDAgeAMDEGA1UdJQQq\n" +
	"MCgGCCsGAQUFBwMDBggrBgEFBQcDAQYIKwYBBQUHAwQGCCsGAQUFBwMIMA0GCSqG\n" +
	"SIb3DQEBCwUAA4IBAQBRfpNRu79i47yp73LWTKrnZRiLC4JAI3I3w5TTx8m2tYkq\n" +
	"tkSCP3Sn4y6VjKqo9Xtlt/bBLypw7XAOZOUZLEaoCjwRmAwq74VHAxDZO1LfFlKd\n" +
	"au8G3xhKjc5prOMJ2g4DELOcyDoLDlwYqQ/jfG/t8b0P37yakFVffSzIA7D0BjmS\n" +
	"OnWrGOJO/IJZjiaTdQkg+n5jk4FNqhwW91em64/M3MOmib3plnl89MgR90kuvQOV\n" +
	"ctDBylt8M61MgnbzeunAq4aKYJc4IeeIH++g4F3/pqyoC95sAZP+A6+LkmBDOcyE\n" +
	"5wUmNtUsL9xxKIUCvPR1JtiLNxHrfendWiuJnW1M\n" +
	"-----END CERTIFICATE-----"
var ekuWrongValuesCodeLeaf = parseCertificateFromString(ekuWrongValuesCodeLeafPem)

func TestFailEkuWrongValuesCodeLeaf(t *testing.T) {
	err := validateLeafCertificate(ekuWrongValuesCodeLeaf, x509.ExtKeyUsageCodeSigning)
	assertErrorEqual("certificate with subject \"CN=Hello\": extended key usage must not contain ServerAuth eku", err, t)
}

var ekuMissingCodeSigningLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICzDCCAbSgAwIBAgIJAJtYOfTu82KRMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAzMTMxM1oYDzIxMjIwNjAxMDMxMzEzWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQN\n" +
	"GJKHE6cdcmrHkxXOTawWgYEF1X42IOK7gAXFg+KBPHPw4npDjUclLX0sY3XjBuhT\n" +
	"wI5DRATSNTV2ba3+DpFuH3D+Hbfjil91AG8XzormUPOOCbZqJxSKYAIZfPQGdUvV\n" +
	"UBulnbDsije00HoNZ03IvdjxbB/9y6a3qQEvIUaEjaZBH3s/YYQIiEmKu6eDpj3R\n" +
	"PnUcrP5b7jBMA/Vb8joLM0InzqGPRLPFAPf5womAjxZSsrgyVeA1xSm+6KtXMmaA\n" +
	"IKYwNVAOnhfqgUk0tlaRyXXji2T1M9w9l5XUA1iNOMcjTUTfFa5KW7c0TLTcK6vW\n" +
	"Eq1BEXUEw7HP7DQUjycCAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM\n" +
	"MAoGCCsGAQUFBwMJMA0GCSqGSIb3DQEBCwUAA4IBAQCSr6A/YAMd6lisgipR0UCA\n" +
	"4Ye/1kl0jglT7stLTfftSeXgCKXYlwus9VSpZBtg+RvJkihlLNT6vtsiTMfJUBBc\n" +
	"jALLKYUQuCw9sReAbfvecIfc2bUve6X8isLWDVnxlC1udx2WG3lIfW2Sgs/dYeZW\n" +
	"yqLTagK5GLlDfg9gBpHLmQYOmshhI85ObOioUAiWTW+S6mx4Bphgl7dlcUabJxEJ\n" +
	"MpJJiGPkUUUCuYkp31E7S4JRbSXSkaHefZxB5fvhlbnACeqnOtMG/IKaTjCUemkK\n" +
	"ZRmJ0Al1PTWs+Dn8zLzexP/LkmQZU/FUMxeat/dAnc2blDbVnAsvcvnutXGHoZH5\n" +
	"-----END CERTIFICATE-----"
var ekuMissingCodeSigningLeaf = parseCertificateFromString(ekuMissingCodeSigningLeafPem)

func TestFailEkuMissingCodeSigningLeaf(t *testing.T) {
	err := validateLeafCertificate(ekuMissingCodeSigningLeaf, x509.ExtKeyUsageCodeSigning)
	assertErrorEqual("certificate with subject \"CN=Hello\": extended key usage must contain CodeSigning eku", err, t)
}

// ---------------- Time-Stamping Leaf Validations ----------------

func TestValidFullOptionsTimeLeaf(t *testing.T) {
	if err := validateLeafCertificate(timeStampingCert, x509.ExtKeyUsageTimeStamping); err != nil {
		t.Fatal(err)
	}
}

var ekuWrongValuesTimeLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIIC6jCCAdKgAwIBAgIJAJOlT2AUbsZiMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAzMTcyM1oYDzIxMjIwNjAxMDMxNzIzWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOZe\n" +
	"9zjKWNlFD/HGrkaAI9mh9Fw1gF8S2tphQD/aPd9IS4HJJEQRkKz5oeHj2g1Y6TEk\n" +
	"plODrKlnoLe+ZFNFFD4xMVV55aQSJDTljCLPwIZt2VewlaAhIImYihOJvJFST1zW\n" +
	"K2NW4eLxt0awbE/YzL6beH4A6UsrcXcnN0KKiu6YD1/d5TezJoTQBMo6fboltuce\n" +
	"P/+RMxyqpvip7nyFF3Yrmhumb7DKJrmSfSjdziI5QoUqzqVgqJ8pXMRb3ZOKb499\n" +
	"d9RRxGkox93iOdSSlaP3FEl8VK9KqnD+MNhjVZbeYTfjm9UVdp91VLP1E/yfMXz+\n" +
	"fZhYkublK6v3GWSEcb0CAwEAAaNFMEMwDgYDVR0PAQH/BAQDAgeAMDEGA1UdJQQq\n" +
	"MCgGCCsGAQUFBwMIBggrBgEFBQcDAQYIKwYBBQUHAwQGCCsGAQUFBwMIMA0GCSqG\n" +
	"SIb3DQEBCwUAA4IBAQCaQZ+ws93F1azT6SKBYvBRBCj07+2DtNI83Q53GxrVy2vU\n" +
	"rP1ULX7beY87amy6kQcqnQ0QSaoLK+CDL88pPxR2PBzCauz70rMRY8O/KrrLcfwd\n" +
	"D5HM9DcbneqXQyfh0ZQpt0wK5wux0MFh2sAEv76jgYBMHq2zc+19skAW/oBtTUty\n" +
	"i/IdOVeO589KXwJzEJmKiswN9zKo9KGgAlKS05zohjv40AOCAs+8Q2lOJjRMq4Ji\n" +
	"z21qor5e/5+NnGY+2p4A7PbN+QnDdRC3y16dESRN50o5x6CwUWQO74+uRjrAWYCm\n" +
	"f/Y7qdOf5zZbY21n8KnLcFOsKhwv4t40Y/LQqN/L\n" +
	"-----END CERTIFICATE-----"
var ekuWrongValuesTimeLeaf = parseCertificateFromString(ekuWrongValuesTimeLeafPem)

func TestFailEkuWrongValuesTimeLeaf(t *testing.T) {
	err := validateLeafCertificate(ekuWrongValuesTimeLeaf, x509.ExtKeyUsageTimeStamping)
	assertErrorEqual("certificate with subject \"CN=Hello\": extended key usage must not contain ServerAuth eku", err, t)
}

var ekuMissingTimeStampingLeafPem = "-----BEGIN CERTIFICATE-----\n" +
	"MIICzDCCAbSgAwIBAgIJAJtYOfTu82KRMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV\n" +
	"BAMMBUhlbGxvMCAXDTIyMDYyNTAzMTMxM1oYDzIxMjIwNjAxMDMxMzEzWjAQMQ4w\n" +
	"DAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQN\n" +
	"GJKHE6cdcmrHkxXOTawWgYEF1X42IOK7gAXFg+KBPHPw4npDjUclLX0sY3XjBuhT\n" +
	"wI5DRATSNTV2ba3+DpFuH3D+Hbfjil91AG8XzormUPOOCbZqJxSKYAIZfPQGdUvV\n" +
	"UBulnbDsije00HoNZ03IvdjxbB/9y6a3qQEvIUaEjaZBH3s/YYQIiEmKu6eDpj3R\n" +
	"PnUcrP5b7jBMA/Vb8joLM0InzqGPRLPFAPf5womAjxZSsrgyVeA1xSm+6KtXMmaA\n" +
	"IKYwNVAOnhfqgUk0tlaRyXXji2T1M9w9l5XUA1iNOMcjTUTfFa5KW7c0TLTcK6vW\n" +
	"Eq1BEXUEw7HP7DQUjycCAwEAAaMnMCUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM\n" +
	"MAoGCCsGAQUFBwMJMA0GCSqGSIb3DQEBCwUAA4IBAQCSr6A/YAMd6lisgipR0UCA\n" +
	"4Ye/1kl0jglT7stLTfftSeXgCKXYlwus9VSpZBtg+RvJkihlLNT6vtsiTMfJUBBc\n" +
	"jALLKYUQuCw9sReAbfvecIfc2bUve6X8isLWDVnxlC1udx2WG3lIfW2Sgs/dYeZW\n" +
	"yqLTagK5GLlDfg9gBpHLmQYOmshhI85ObOioUAiWTW+S6mx4Bphgl7dlcUabJxEJ\n" +
	"MpJJiGPkUUUCuYkp31E7S4JRbSXSkaHefZxB5fvhlbnACeqnOtMG/IKaTjCUemkK\n" +
	"ZRmJ0Al1PTWs+Dn8zLzexP/LkmQZU/FUMxeat/dAnc2blDbVnAsvcvnutXGHoZH5\n" +
	"-----END CERTIFICATE-----"
var ekuMissingTimeStampingLeaf = parseCertificateFromString(ekuMissingTimeStampingLeafPem)

func TestFailEkuMissingTimeStampingLeaf(t *testing.T) {
	err := validateLeafCertificate(ekuMissingTimeStampingLeaf, x509.ExtKeyUsageTimeStamping)
	assertErrorEqual("certificate with subject \"CN=Hello\": extended key usage must contain TimeStamping eku", err, t)
}

// ---------------- Utility Methods ----------------

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
