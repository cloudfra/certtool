# Code Signing Certificate Generation

**Date:** 2026-06-28
**Branch:** codesign

## Summary

Add code signing certificate generation to certtool. Primary target is Windows binary signing (via `signtool.exe` + PKCS#12). Linux binary signing (via `osslsigncode` + PEM) is secondary. A `--code-sign` flag switches the cert from TLS mode to code signing mode; a `--target` flag selects a named platform profile that sets secure defaults for that Windows version or Linux.

## Target Profiles

Each profile encodes everything that differs between platforms/versions so users don't need to know the specifics.

| Target | Aliases | Key Type | Signature Algorithm | PKCS#12 Encoding |
|---|---|---|---|---|
| `windows7` | `win7`, `windows8`, `win8` | RSA-2048 | SHA256WithRSA | Legacy (3DES) |
| `windows10` | `win10` | ECDSA P-256 | ECDSAWithSHA256 | Modern (AES-256) |
| `windows11` | `win11` | ECDSA P-256 | ECDSAWithSHA256 | Modern (AES-256) |
| `linux` | — | ECDSA P-256 | ECDSAWithSHA256 | None (PEM output) |

**Default target** when `--code-sign` is used: `windows10`.

The profile sets defaults only. `--key-type` can still override the key algorithm and length for any target (e.g. RSA-4096 on `windows10`).

Windows 7 uses legacy PKCS#12 encoding (3DES) because Windows 7 cannot import AES-256-based PFX files. Windows 10/11 uses modern AES-256 encoding.

## Cert Attributes

Code signing certs differ from the existing TLS certs in three fields of the `x509.Certificate` template:

| Field | TLS (existing) | Code Signing |
|---|---|---|
| `KeyUsage` | `KeyEncipherment \| DigitalSignature` | `DigitalSignature` only |
| `ExtKeyUsage` | `ServerAuth, ClientAuth` | `CodeSigning` |
| Auto-SANs | `localhost`, `127.0.0.1` always appended | Not added |

Subject fields (CN, O, OU, C, L, ST), validity duration, serial number, and CA chain support all remain configurable and behave identically to the TLS path.

## Output Format

### Windows targets (`windows7`, `windows10`, `windows11`)
- Output: single PKCS#12 (`.pfx`) file bundling the public cert and private key
- CLI flag: `--pfx-output` (default: `codesign.pfx`)
- Password flag: `--pfx-password` (default: empty string — `signtool.exe` accepts passwordless PFX)
- PEM files (`--public-certificate`, `--private-key`) are not written for Windows targets in code-signing mode

### Linux target
- Output: PEM pair via existing `--public-certificate` / `--private-key` flags
- No PKCS#12 generated

## Data Model Changes

### `Args` struct (two new fields)
```go
type Args struct {
    // existing fields unchanged ...

    // CodeSigning switches the cert to code signing mode (ExtKeyUsageCodeSigning,
    // DigitalSignature only, no auto-SANs).
    CodeSigning bool

    // Target selects a named platform profile. Valid values: windows7, windows10,
    // windows11, linux (and their aliases). Only used when CodeSigning is true.
    // Default: "windows10".
    Target string

    // PFXPassword is the password for PKCS#12 output. Empty string = no password.
    PFXPassword string
}
```

### `KeyPair` struct (one new field)
```go
type KeyPair struct {
    PublicCertificate []byte  // PEM — always populated
    PrivateKey        []byte  // PEM — always populated
    PFX               []byte  // PKCS#12 — populated for Windows targets only
}
```

## New CLI Flags

Added to the existing single-command CLI in `cmd/certtool/certtool.go`:

```
--code-sign            Switch to code signing cert mode (default: false)
--target=windows10     Platform profile; sets key type, sig alg, output format
--pfx-output=...       Path for .pfx output file (default: codesign.pfx)
--pfx-password=...     Password for .pfx file (default: empty)
```

Existing flags (`--public-certificate`, `--private-key`, `--key-type`, `--ca`, subject flags, `--parent-*`) remain unchanged and continue to work in both TLS and code-signing modes.

## New Dependency

`software.sslmate.com/src/go-pkcs12` — the standard Go PKCS#12 library. Required for both legacy (3DES, Win7) and modern (AES-256, Win10+) PKCS#12 encoding. No other Go library handles both encoding modes.

## File Structure

```
pkg/certtool/
  certtool.go      — extend Args, KeyPair; add code-signing cert template logic
  profiles.go      — TargetProfile struct, named profiles map, alias resolution
  pkcs12.go        — ToPFX() wrapping go-pkcs12 with profile-driven encoding choice
  certtool_test.go — existing tests (unchanged) + new code signing tests
  profiles_test.go — profile lookup, alias resolution, override behavior
  pkcs12_test.go   — PFX round-trip tests

cmd/certtool/
  certtool.go      — new CLI flags, wiring to library
```

## Error Handling

- Unknown `--target` value → clear error listing valid targets
- `--target` set without `--code-sign` → ignored with a warning logged
- `--pfx-output` set without `--code-sign` or with Linux target → ignored with a warning
- `--pfx-password` with Linux target → ignored with a warning
- `--key-type` override with ECDSA on a `windows7` target → warning logged ("ECDSA code signing certs are not supported by Windows 7 signtool.exe"); generation proceeds since it's an explicit user override

## Testing

- Unit tests for profile lookup and alias resolution
- Unit tests for cert template attributes (KeyUsage, ExtKeyUsage, no auto-SANs) in code-signing mode
- Round-trip test: generate PFX → decode with go-pkcs12 → verify cert fields and key match
- Tests for both legacy (Win7) and modern (Win10) PKCS#12 encoding
- Existing TLS cert tests unchanged and must continue to pass
