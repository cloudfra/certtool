---
name: certtool
description: Use when a task needs X.509 certificates or private keys - self-signed TLS/HTTPS certificates for local development or tests, a private root or intermediate CA, mutual TLS client certificates, certificate hierarchies, Windows or Linux code signing certificates (.pfx for signtool, PEM for osslsigncode), or a root CA kept on a YubiKey - and certtool is available or can be installed.
---

# certtool

## Overview

`certtool` generates X.509 certificates and private keys from command-line flags or a YAML spec. It is built for automation: it never prompts, so every input comes from flags or environment variables.

| Behavior | Detail |
| -------- | ------ |
| Output | PEM files (`.crt`, `.key`) and PKCS#12 (`.pfx`) for Windows code signing. Key and `.pfx` files are written with mode `0600`. |
| Logs | Everything goes to stderr; stdout stays empty. Each generated file is logged as `INFO generated certificate {"cn": ..., "cert": ..., "key": ...}`. |
| Exit codes | `0` success. `1` the run failed; the `ERROR certtool failed {"error": "..."}` line names the flag at fault and why. `2` a flag could not be parsed (usage is printed). |
| Existing files | A single certificate overwrites its files without asking; check the destination first. `--spec` and `--chain` reuse certificates whose `.crt` and `.key` already exist and only generate what is missing; `--overwrite` regenerates everything. |
| Help | `certtool --help` (printed to stderr) lists every flag. See [references/flags.md](references/flags.md). |

## Getting the binary

Check `certtool --version` first. Otherwise download a release build, or install with Go:

```bash
# Linux amd64. Other builds: certtool-linux_arm64, certtool-darwin_arm64, certtool-windows_amd64.exe, certtool-windows_arm64.exe
curl -fsSL -o certtool https://github.com/cloudfra/certtool/releases/latest/download/certtool-linux_amd64 && chmod +x certtool

go install github.com/cloudfra/certtool/cmd/certtool@latest
```

YubiKey support is in the Windows downloads, and on Linux and macOS only in builds made with `CGO_ENABLED=1` and the PC/SC library (`libpcsclite-dev` on Debian/Ubuntu).

## Choosing a mode

| The user wants | Use |
| -------------- | --- |
| One certificate and key | Flags only (writes `app.crt` and `app.key` by default) |
| A CA and certificates it signs, few files | `--ca`, then `--parent-public-certificate` with `--parent-private-key` |
| A regular hierarchy (root, intermediates, leaves) | `--chain 1,2,3 --output-dir DIR` |
| Specific names, hostnames, or mixed trees | `--spec FILE --output-dir DIR` ([references/spec-format.md](references/spec-format.md)) |
| A spec for a common situation | `--scenario NAME --export-spec FILE` first (web, local-dev, mtls, microservices, database, active-directory, kubernetes, vpn, eap-tls, iot, kafka, docker, ios, android, android-signing, code-sign, proxy), then edit it and run `--spec FILE`. Prefer this to writing a spec from scratch: it picks key types, validities, and name constraints, and explains them in comments |
| A spec to start editing from | `--export-spec FILE` with `--chain` or plain flags; writes the YAML and no certificates |
| Code signing | `--code-sign --target windows10\|windows11\|windows7\|linux\|android` |
| A root CA whose key never leaves hardware | `--yubikey-generate-root` once, then `--yubikey` |
| Key files that need a YubiKey (or another age key) to read | `--encrypt-to age1yubikey1...,age1...`; later runs that reuse or sign with them add `--age-yubikey` or `--age-identity-file` |

## Recipes

```bash
# Local HTTPS. localhost and 127.0.0.1 are always added as SANs.
certtool --common-name myapp.localhost --hostnames myapp.localhost,192.168.1.20 \
  --key-type ECDSA-256 --public-certificate dev.crt --private-key dev.key

# Private CA, then a server certificate signed by it
certtool --ca --common-name "Acme Root CA" --organization Acme --key-type ECDSA-384 \
  --validity 87600h --max-path-len 0 --permitted-dns-domains example.com \
  --public-certificate root-ca.crt --private-key root-ca.key
certtool --common-name api.example.com --organization Acme --hostnames api.example.com \
  --parent-public-certificate root-ca.crt --parent-private-key root-ca.key \
  --public-certificate api.crt --private-key api.key

# Commented spec for web servers and code signing: review certs.yaml, then generate it
certtool --scenario web,code-sign --organization Acme --hostnames api.example.com --export-spec certs.yaml
certtool --spec certs.yaml --output-dir certs   # .pfx password from CERTTOOL_PFX_PASSWORD

# Hierarchy: 1 root, 2 intermediates, 3 leaves under each (files named after each CN)
certtool --chain 1,2,3 --common-name svc --organization Acme --output-dir certs

# Windows code signing: writes codesign.pfx (ECDSA P-256, AES-256)
certtool --code-sign --common-name "Acme Release Signing" --organization Acme \
  --pfx-output release.pfx   # password from CERTTOOL_PFX_PASSWORD

# Linux code signing (osslsigncode): PEM certificate and key, no .pfx
certtool --code-sign --target linux --public-certificate sign.crt --private-key sign.key
```

Check the result with `openssl x509 -in api.crt -noout -subject -issuer -ext subjectAltName` and `openssl verify -CAfile root-ca.crt api.crt`.

## YubiKey root CA

```bash
# The PIN comes from the environment so it stays out of the command line and logs.
export CERTTOOL_YUBIKEY_PIN="$YUBIKEY_PIN"

# Once: create the root key on the YubiKey (slot 9c) and write its certificate to root.crt
certtool --yubikey-generate-root --common-name "Acme Root CA" --organization Acme \
  --key-type ECDSA-384 --validity 87600h --public-certificate root.crt

# Sign with it: a single certificate, --chain, or the top-level entries of --spec
certtool --yubikey --ca --common-name "Acme Issuing CA" --organization Acme \
  --public-certificate issuing-ca.crt --private-key issuing-ca.key
```

- Signing may make the YubiKey blink and wait for a touch; roots made by certtool need one for every signature by default. certtool logs `touch it if it is blinking`; tell the user to touch the key. This is the only time certtool waits.
- A warning that the YubiKey still uses its factory default PIN or management key means the root CA is not protected; pass it on to the user with the `ykman` commands it names.
- `--yubikey-serial` picks one YubiKey when several are connected. `--yubikey-slot` picks another slot (`9a`, `9c`, `9d`, `9e`, `82`-`95`).
- `--yubikey-generate-root` refuses a slot that already holds a certificate. Only add `--yubikey-overwrite` when the user has said to destroy the existing key; it cannot be undone.

## Rules

- Never invent a PIN, management key, or `.pfx` password. If one is needed and not given, ask the user, or let certtool fail and report its error.
- Pass secrets through `CERTTOOL_PFX_PASSWORD`, `CERTTOOL_YUBIKEY_PIN`, `CERTTOOL_YUBIKEY_MANAGEMENT_KEY`, and `CERTTOOL_AGE_IDENTITY`, not on the command line.
- With `--encrypt-to`, include a recovery recipient besides the YubiKey's, if the user has one; a key encrypted to a single YubiKey is lost with it. In specs, use `pfxPasswordEnv`, never `pfxPassword`.
- Never commit generated `.key` or `.pfx` files. Add them to `.gitignore` when generating inside a repository.
- Set `--organization` (and the other subject flags) for anything beyond a throwaway test. The defaults (`cloudfra`, `gows`, `Seattle`, `WA`, `US`) are placeholders.

## Common mistakes

| Mistake | Fix |
| ------- | --- |
| `--validity 365d` (exit 2) | Go durations only: `8760h` is 1 year, `87600h` is 10 years. |
| `parent certificate ... is limited to TLS server and TLS client` | Roots made with `--ca` or a spec CA can only issue TLS certificates. Leave code signing certificates standalone, or sign them with `--yubikey`. |
| `parent certificate ... is not a CA certificate` or `... expired at` | The parent must be a current CA made with `--ca`. A child's validity is cut to end when its parent's does. |
| `--output-dir` ignored | It only applies to `--chain` and `--spec`. Put the directory in `--public-certificate` and `--private-key` instead. |
| `--parent-public-certificate is required with --parent-private-key` | The two parent flags always go together. |
| `--yubikey needs the YubiKey PIN` | Set `CERTTOOL_YUBIKEY_PIN` (or `--yubikey-pin`). |
| `--chain would generate the common name ... more than once` | Pick a `--common-name` that differs from the generated CA names (`<organization> Root CA`). |
| `--chain and --spec are mutually exclusive` | Use `--chain ... --export-spec FILE`, edit the file, then run `--spec FILE`. |
| A web server only sends the leaf | Give the server the full chain (for `openssl s_server`, `-cert_chain`). |

Full guides: <https://github.com/cloudfra/certtool/tree/main/docs/use-cases>.
