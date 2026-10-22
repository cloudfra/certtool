# Cert Tool
<!-- markdownlint-disable-next-line MD033 -->
<img src="logo.png" alt="Logo" width="64" height="64" />

[![CI](https://github.com/cloudfra/certtool/actions/workflows/deploy.yaml/badge.svg)](https://github.com/cloudfra/certtool/actions/workflows/deploy.yaml) [![Go Reference](https://pkg.go.dev/badge/github.com/cloudfra/certtool.svg)](https://pkg.go.dev/github.com/cloudfra/certtool) [![codecov](https://codecov.io/gh/cloudfra/certtool/graph/badge.svg?token=UVApxhg6z7)](https://codecov.io/gh/cloudfra/certtool)

A simple tool for generating self-signed X.509 certificates and private keys for TLS and code signing, available as a standalone CLI and Go library.

```bash
# Download (Linux amd64, see Downloads for other builds)
curl -fLo certtool https://github.com/cloudfra/certtool/releases/latest/download/certtool-linux_amd64 && chmod +x certtool

# Self-signed TLS certificate for localhost (writes app.crt and app.key)
./certtool

# Code signing certificate for Windows 10/11 (writes codesign.pfx)
./certtool --code-sign
```

## Features

* Generate self-signed X.509 public certificate and private key pairs in PEM format.
* Generate code signing certificates as PKCS#12 (`.pfx`) files for Windows binary signing with `signtool.exe`.
* Named platform profiles (`windows7`, `windows10`, `windows11`, `linux`) set secure defaults automatically.
* Create CA (root) certificates for establishing a chain of trust.
* Sign certificates with a parent CA to build certificate chains.
* Keep the root CA key on a YubiKey: generate it on the device and sign certificates with it, without the key ever leaving the YubiKey.
* Generate whole certificate hierarchies (root, intermediates, leaves) in one command with `--chain`, or from a YAML spec with `--spec`.
* RSA (2048, 4096-bit) and ECDSA (P-256, P-384, P-521) key algorithms, signed with a hash that matches the key (SHA-256, or SHA-384/SHA-512 for P-384/P-521).
* Subject Alternative Names (SANs) for hostnames and IP addresses.
* Always includes `localhost` and `127.0.0.1` as SANs (TLS mode).
* Configure X.509 subject fields: Country, Organization, Locality, Province, and more.
* Available as a Go library (`github.com/cloudfra/certtool/pkg/certtool`) for programmatic certificate generation.
* Prebuilt binaries for all major operating systems and architectures.

## Usage

Each example writes its files to the current directory. The [use case guides](docs/use-cases/README.md) walk through complete setups, including trusting the certificates and verifying them.

### TLS certificates

```bash
# Self-signed certificate for localhost (RSA-2048, writes app.crt and app.key)
./certtool

# Certificate for your own hostnames and IP addresses
./certtool --common-name myapp.localhost --hostnames myapp.localhost,192.168.1.20 \
  --key-type ECDSA-256 --public-certificate dev.crt --private-key dev.key

# Root CA, then a server certificate signed by it
./certtool --ca --common-name "Acme Root CA" --organization Acme --key-type ECDSA-384 --validity 87600h \
  --max-path-len 0 --permitted-dns-domains example.com \
  --public-certificate root-ca.crt --private-key root-ca.key
./certtool --common-name api.example.com --hostnames api.example.com \
  --parent-public-certificate root-ca.crt --parent-private-key root-ca.key \
  --public-certificate api.crt --private-key api.key
```

Guides: [Local development HTTPS](docs/use-cases/local-development.md), [Private CA and mutual TLS](docs/use-cases/private-ca.md).

### Code signing certificates

```bash
# Windows 10 and 11: ECDSA P-256 in an AES-256 encrypted codesign.pfx
export CERTTOOL_PFX_PASSWORD="$PFX_PASSWORD"   # or --pfx-password
./certtool --code-sign --common-name "Acme Internal Software"

# Windows 7 and 8: RSA-2048 in a legacy 3DES encrypted PFX
./certtool --code-sign --target windows7 --pfx-output codesign-legacy.pfx

# PEM certificate and key for osslsigncode on Linux or macOS
./certtool --code-sign --target linux --public-certificate codesign.crt --private-key codesign.key
```

| Target | Aliases | Key type | Output | Use with |
| ------ | ------- | -------- | ------ | -------- |
| `windows10` *(default)* | `win10` | ECDSA P-256 | PFX, AES-256 | Windows 10/11 `signtool.exe` |
| `windows11` | `win11` | ECDSA P-256 | PFX, AES-256 | Windows 11 `signtool.exe` |
| `windows7` | `win7`, `windows8`, `win8`, `windows8.1`, `win8.1` | RSA-2048 | PFX, 3DES (legacy) | Windows 7/8 `signtool.exe` |
| `linux` | | ECDSA P-256 | PEM certificate and key | `osslsigncode` |

`--key-type` overrides the key type of any target. Guide: [Code signing](docs/use-cases/code-signing.md).

### Certificate hierarchies

`--chain` takes the number of certificates in each layer, from the root down. The last layer is the leaves.

```bash
# One root, two intermediate CAs, and three leaves under each intermediate, in certs/
./certtool --chain 1,2,3 --common-name svc --organization Acme --output-dir certs

# Write the hierarchy as a YAML spec to edit, then generate from it
./certtool --chain 1,2,1 --export-spec certs.yaml
./certtool --spec certs.yaml --output-dir certs
```

Every certificate gets a unique name (for example `Acme Root CA`, `Acme Intermediate CA 1`, `svc 1.2`), so files never overwrite each other. Running `--spec` or `--chain` again reuses the certificates already in `--output-dir`, so adding entries to a spec extends the hierarchy; `--overwrite` regenerates everything ([details](docs/spec.md#running-a-spec-again)). The [certificate spec documentation](docs/spec.md) covers naming, the spec format, `--name-prefix`, and examples for Kubernetes, Active Directory, and databases.

### YubiKey root CA

```bash
# The PIN comes from CERTTOOL_YUBIKEY_PIN or --yubikey-pin; certtool never prompts
read -rs -p "YubiKey PIN: " CERTTOOL_YUBIKEY_PIN && export CERTTOOL_YUBIKEY_PIN

# Once: generate the root CA key on the YubiKey and write its certificate to root.crt
./certtool --yubikey-generate-root --common-name "Acme Root CA" --organization Acme \
  --key-type ECDSA-384 --validity 87600h --public-certificate root.crt

# Sign an intermediate CA with the YubiKey, then sign leaves with the intermediate
./certtool --yubikey --ca --common-name "Acme Issuing CA" --organization Acme \
  --public-certificate issuing-ca.crt --private-key issuing-ca.key
./certtool --common-name api.example.com --hostnames api.example.com \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate api.crt --private-key api.key
```

`--yubikey --spec certs.yaml` does the same from a YAML spec: the YubiKey signs each top-level entry ([example](docs/spec.md#yubikey-root-ca)).

`--yubikey` signs with a root CA that is already on the YubiKey, made by `--yubikey-generate-root` or by any other tool. It works on Windows with the prebuilt downloads, and on Linux, macOS, FreeBSD, and OpenBSD when certtool is built with `CGO_ENABLED=1`. Guide: [YubiKey root CA](docs/use-cases/yubikey-root-ca.md), covering both a new and an existing root, requirements, automation, and troubleshooting.

### Flags

#### TLS flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--public-certificate` | `app.crt` | X.509 public certificate output file |
| `--private-key` | `app.key` | Private key output file |
| `--ca` | `false` | Generate a root/CA certificate |
| `--max-path-len` | `-1` (no limit) | With `--ca` or `--yubikey-generate-root`: how many CAs may sit below the CA (`0` = it signs only leaves) |
| `--permitted-dns-domains` | | With `--ca` or `--yubikey-generate-root`: comma-separated DNS domains that certificates below the CA may use, as critical name constraints |
| `--permitted-ip-ranges` | | With `--ca` or `--yubikey-generate-root`: comma-separated CIDR ranges that certificates below the CA may use |
| `--key-type` | `RSA-2048` | Key algorithm and length (`RSA-2048`, `RSA-4096`, `ECDSA-256`, `ECDSA-384`, `ECDSA-521`) |
| `--hostnames` | | Comma-separated hostnames and IP addresses to add as SANs |
| `--validity` | `8760h` (1 year) | How long the certificate is valid for, as a Go duration (e.g. `8760h`, `720h`, `24h`) |
| `--common-name` | | Common Name (CN) field of the X.509 subject (defaults to `--organization`) |
| `--country` | `US` | Country (C) field of the X.509 subject |
| `--organization` | `cloudfra` | Organization (O) field of the X.509 subject |
| `--organizational-unit` | `gows` | Organizational Unit (OU) field of the X.509 subject |
| `--locality` | `Seattle` | Locality/city (L) field of the X.509 subject |
| `--province` | `WA` | Province/state (ST) field of the X.509 subject |
| `--parent-public-certificate` | | Parent CA public certificate for signing |
| `--parent-private-key` | | Parent CA private key for signing (unencrypted PEM: PKCS#1, SEC 1, or PKCS#8) |

#### Code signing flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--code-sign` | `false` | Generate a code signing certificate instead of a TLS certificate |
| `--target` | `windows10` | Platform profile: `windows7`, `windows10`, `windows11`, `linux` (and aliases) |
| `--pfx-output` | `codesign.pfx` | Output path for the PKCS#12 (`.pfx`) file (Windows targets) |
| `--pfx-password` | | Password for the `.pfx` file (defaults to `CERTTOOL_PFX_PASSWORD`; empty = no password) |

#### Hierarchy flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--chain` | | Number of certificates per layer, from the root down (`3`, `1,1`, `1,2,3`). The last layer is the leaves. Cannot be combined with `--spec` |
| `--name-prefix` | | Prefix placed in front of the name of every certificate generated by `--chain` |
| `--spec` | | Path to a YAML spec describing the certificates to generate |
| `--output-dir` | `.` | Output directory for certificates generated by `--spec` or `--chain` |
| `--overwrite` | `false` | With `--spec` or `--chain`, regenerate every certificate instead of reusing the files already in `--output-dir` |
| `--export-spec` | | Write the resolved spec as YAML to this path instead of generating certificates. Works with `--chain`, `--spec`, or plain flags |

#### YubiKey flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--yubikey` | `false` | Sign with the root CA stored on a YubiKey instead of `--parent-public-certificate`/`--parent-private-key` |
| `--yubikey-generate-root` | `false` | Generate a root CA key on a YubiKey, store its self-signed certificate there, and write it to `--public-certificate`. Supports `ECDSA-256`, `ECDSA-384`, `RSA-2048`, and `RSA-4096` (firmware 5.7+) |
| `--yubikey-serial` | | Serial number of the YubiKey to use. Required only when more than one is connected |
| `--yubikey-slot` | `9c` | PIV slot holding the root CA: `9a`, `9c`, `9d`, `9e`, or `82` through `95` |
| `--yubikey-pin` | | YubiKey PIN, required by `--yubikey` and `--yubikey-generate-root` (defaults to `CERTTOOL_YUBIKEY_PIN`; certtool never prompts) |
| `--yubikey-management-key` | | Management key in hex for `--yubikey-generate-root` (defaults to `CERTTOOL_YUBIKEY_MANAGEMENT_KEY`, otherwise the PIN-protected or factory default key) |
| `--yubikey-touch-policy` | `always` | Touch requirement for a key made by `--yubikey-generate-root`: `always` (every signature), `cached` (one touch per 15 seconds), or `never` |
| `--yubikey-overwrite` | `false` | Allow `--yubikey-generate-root` to replace a slot that already holds a certificate. The old key is destroyed |

#### General flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--version` | `false` | Print version and build information, then exit |

## AI agents

certtool ships a skill that teaches AI agents how to use it: choosing a mode, recipes, handling secrets, and common mistakes. It lives in [skills/certtool](skills/certtool/SKILL.md) and follows the [Agent Skills](https://agentskills.io) format, so any agent that supports skills can load it. In Claude Code, install it as a plugin:

```text
/plugin install certtool --marketplace cloudfra/certtool
```

Claude Code versions before 2.1.275 take two steps: `/plugin marketplace add cloudfra/certtool`, then `/plugin install certtool@certtool`.

[llms.txt](llms.txt) indexes the documentation for language models, and [AGENTS.md](AGENTS.md) guides agents that change certtool itself.

## Downloads

| OS | Arch | Link |
| -- | ---- | ---- |
| Linux | amd64 | `curl -fLo certtool https://github.com/cloudfra/certtool/releases/latest/download/certtool-linux_amd64 && chmod +x certtool` |
| Linux | arm64 | `curl -fLo certtool https://github.com/cloudfra/certtool/releases/latest/download/certtool-linux_arm64 && chmod +x certtool` |
| macOS | arm64 | `curl -fLo certtool https://github.com/cloudfra/certtool/releases/latest/download/certtool-darwin_arm64 && chmod +x certtool` |
| Windows | amd64 | `$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri "https://github.com/cloudfra/certtool/releases/latest/download/certtool-windows_amd64.exe" -OutFile "certtool.exe" -UseBasicParsing` |
| Windows | arm64 | `$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri "https://github.com/cloudfra/certtool/releases/latest/download/certtool-windows_arm64.exe" -OutFile "certtool.exe" -UseBasicParsing` |

For other platforms, install with Go: `go install github.com/cloudfra/certtool/cmd/certtool@latest`.

## Docker Images

* [certtool](https://hub.docker.com/r/cloudfra/certtool/tags)

Images are tagged by release (there is no `latest` tag):

```bash
docker run --rm docker.io/cloudfra/certtool:v0.7.0 --version
```

## Build

![example workflow](https://github.com/cloudfra/certtool/actions/workflows/deploy.yaml/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/cloudfra/certtool)](https://goreportcard.com/report/github.com/cloudfra/certtool) [![Go Reference](https://pkg.go.dev/badge/github.com/cloudfra/certtool.svg)](https://pkg.go.dev/github.com/cloudfra/certtool) [![codecov](https://codecov.io/gh/cloudfra/certtool/branch/main/graph/badge.svg)](https://codecov.io/gh/cloudfra/certtool)

Install the [latest stable version of Go](https://golang.org/dl/).

```bash
# Clone the repository
git clone git@github.com:cloudfra/certtool.git
# Build the binary
make -j$(nproc)
```

## Test

```bash
make test
make bench
```
