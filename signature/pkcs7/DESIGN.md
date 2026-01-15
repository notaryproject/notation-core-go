# PKCS#7 Envelope Implementation for dm-verity

This document explains the PKCS#7 signature envelope implementation in notation-core-go.

## Overview

The PKCS#7 (CMS - Cryptographic Message Syntax) envelope produces signatures compatible with Linux kernel dm-verity verification. This is the same format produced by:

```bash
openssl smime -sign -noattr -binary -in content -signer cert.pem -inkey key.pem -outform DER
```

## Architecture

### signerAdapter Pattern

The key innovation is the `signerAdapter` pattern that enables **both local and remote signers** (like Azure Key Vault) to work with the Mozilla PKCS#7 library:

```
┌─────────────────────┐
│   signature.Signer  │  ← Your signer (local key, AKV, plugin)
│   Sign(payload)     │
└─────────┬───────────┘
          │ returns (sig, certs)
          ▼
┌─────────────────────┐
│   signerAdapter     │  ← Wraps pre-computed signature
│   crypto.Signer     │
└─────────┬───────────┘
          │ passed to
          ▼
┌─────────────────────┐
│   Mozilla pkcs7     │  ← Builds ASN.1 structure
│   SignWithoutAttr() │
└─────────────────────┘
```

**How it works:**

1. Call `req.Signer.Sign(payload)` to get signature bytes + certs from any signer
2. Create `signerAdapter` that implements `crypto.Signer`
3. `signerAdapter.Sign()` returns the pre-computed signature (doesn't re-sign)
4. Mozilla library builds PKCS#7 ASN.1 structure using the adapter

**Why this works:**
The Mozilla library calls `crypto.Signer.Sign()` expecting to perform signing, but our adapter just returns the already-computed signature. The library doesn't know the difference and builds valid PKCS#7 output.

### Code Structure

```go
// signerAdapter wraps a pre-computed signature to satisfy crypto.Signer
type signerAdapter struct {
    sig   []byte              // pre-computed from actual signer
    certs []*x509.Certificate
}

func (a *signerAdapter) Public() crypto.PublicKey {
    return a.certs[0].PublicKey
}

func (a *signerAdapter) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    return a.sig, nil  // Return pre-computed signature
}
```

## Comparison to JWS/COSE

| Aspect | JWS | COSE | PKCS#7 |
|--------|-----|------|--------|
| Implements Envelope | ✅ | ✅ | ✅ |
| Uses base.Envelope | ✅ | ✅ | ✅ |
| Signer support | Any | Any | Any (via adapter) |
| Encoding | JSON | CBOR | ASN.1 DER |
| Library | go-jwt | go-cose | go.mozilla.org/pkcs7 |
| Use case | OCI artifacts | OCI artifacts | dm-verity kernel |

## Kernel Compatibility Settings

```go
// SHA-256 required (kernel rejects SHA-1)
sd.SetDigestAlgorithm(gopkcs7.OIDDigestAlgorithmSHA256)

// Set encryption algorithm based on key type
sd.SetEncryptionAlgorithm(gopkcs7.OIDEncryptionAlgorithmRSA)

// No authenticated attributes (-noattr mode)
sd.SignWithoutAttr(cert, adapter, gopkcs7.SignerInfoConfig{})

// Detached signature (kernel provides content separately)
sd.Detach()
```

## Supported Key Types

| Key Type | Supported | OID |
|----------|-----------|-----|
| RSA-2048 | ✅ | OIDEncryptionAlgorithmRSA |
| RSA-3072 | ✅ | OIDEncryptionAlgorithmRSA |
| RSA-4096 | ✅ | OIDEncryptionAlgorithmRSA |
| ECDSA P-256 | ✅ | OIDEncryptionAlgorithmECDSAP256 |
| ECDSA P-384 | ✅ | OIDEncryptionAlgorithmECDSAP384 |
| ECDSA P-521 | ✅ | OIDEncryptionAlgorithmECDSAP521 |

**Note:** Linux kernel dm-verity currently only supports RSA. ECDSA is included for completeness but may not work with kernel verification.

## References

- [RFC 5652 - Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652)
- [Mozilla PKCS#7 Library](https://github.com/mozilla-services/pkcs7)
- [Linux Kernel dm-verity](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
