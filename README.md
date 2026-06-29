# Cert Tool

A simple tool for generating self-signed X.509 certificates and private keys, available as a standalone CLI and Go library.

```bash
# Download (Linux amd64, see Downloads for other builds)
curl -o certtool -O -L https://github.com/cloudfra/certtool/releases/latest/download/certtool-amd64; chmod +x certtool

# Generate a self-signed certificate (outputs app.cert and app.key)
./certtool
```

## Features

* Generate self-signed X.509 public certificate and private key pairs in PEM format.
* Create CA (root) certificates for establishing a chain of trust.
* Sign certificates with a parent CA to build certificate chains.
* RSA (2048, 4096-bit) and ECDSA (P-224, P-256, P-384, P-521) key algorithms.
* Subject Alternative Names (SANs) for hostnames and IP addresses.
* Always includes `localhost` and `127.0.0.1` as SANs.
* Configure X.509 subject fields: Country, Organization, Locality, Province, and more.
* Available as a Go library (`github.com/cloudfra/certtool/pkg/certtool`) for programmatic certificate generation.
* Prebuilt binaries for all major operating systems and architectures.

## Usage

```bash
# Generate a self-signed certificate with defaults (RSA-2048, outputs app.cert and app.key)
./certtool

# Generate a certificate for specific hostnames and IPs
./certtool --hostnames example.com,192.168.1.1

# Generate an ECDSA-256 certificate with custom output files
./certtool --key-type ECDSA-256 --public-certificate server.crt --private-key server.key

# Generate a root CA certificate
./certtool --ca --public-certificate ca.crt --private-key ca.key

# Generate a certificate signed by a parent CA
./certtool \
  --parent-public-certificate ca.crt --parent-private-key ca.key \
  --public-certificate server.crt --private-key server.key
```

### Flags

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--public-certificate` | `app.cert` | X.509 public certificate output file |
| `--private-key` | `app.key` | Private key output file |
| `--ca` | `false` | Generate a root/CA certificate |
| `--key-type` | `RSA-2048` | Key algorithm and length (`RSA-2048`, `RSA-4096`, `ECDSA-224`, `ECDSA-256`, `ECDSA-384`, `ECDSA-521`) |
| `--hostnames` | | Comma-separated hostnames and IP addresses to add as SANs |
| `--country` | `US` | Country (C) field of the X.509 subject |
| `--organization` | `cloudfra` | Organization (O) field of the X.509 subject |
| `--organizational-unit` | `gows` | Organizational Unit (OU) field of the X.509 subject |
| `--locality` | `Seattle` | Locality/city (L) field of the X.509 subject |
| `--province` | `WA` | Province/state (ST) field of the X.509 subject |
| `--parent-public-certificate` | | Parent CA public certificate for signing |
| `--parent-private-key` | | Parent CA private key for signing |

## Downloads

| OS | Arch | Link |
| -- | ---- | ---- |
| Linux | amd64 | `curl -O -L https://github.com/cloudfra/certtool/releases/latest/download/certtool-amd64` |
| Linux | arm | `curl -O -L https://github.com/cloudfra/certtool/releases/latest/download/certtool-arm` |
| Linux | arm64 | `curl -O -L https://github.com/cloudfra/certtool/releases/latest/download/certtool-arm64` |
| Linux | 386 | `curl -O -L https://github.com/cloudfra/certtool/releases/latest/download/certtool-386` |
| Windows | amd64 | `$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri "https://github.com/cloudfra/certtool/releases/latest/download/certtool-amd64.exe" -OutFile "certtool-amd64.exe" -UseBasicParsing` |
| Windows | 386 | `$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri "https://github.com/cloudfra/certtool/releases/latest/download/certtool-386.exe" -OutFile "certtool-386.exe" -UseBasicParsing` |
| Windows | arm64 | `$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri "https://github.com/cloudfra/certtool/releases/latest/download/certtool-arm64.exe" -OutFile "certtool-arm64.exe" -UseBasicParsing` |
| macOS | amd64 | `curl -O -L https://github.com/cloudfra/certtool/releases/latest/download/certtool-amd64-darwin` |
| macOS | arm64 | `curl -O -L https://github.com/cloudfra/certtool/releases/latest/download/certtool-arm64-darwin` |

## Docker Images

* [certtool](https://hub.docker.com/r/cloudfra/certtool/tags)

```bash
docker pull docker.io/cloudfra/certtool
```

## Build

![example workflow](https://github.com/cloudfra/certtool/actions/workflows/deploy.yml/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/cloudfra/certtool)](https://goreportcard.com/report/github.com/cloudfra/certtool) [![Go Reference](https://pkg.go.dev/badge/github.com/cloudfra/certtool.svg)](https://pkg.go.dev/github.com/cloudfra/certtool) [![codecov](https://codecov.io/gh/cloudfra/certtool/branch/main/graph/badge.svg)](https://codecov.io/gh/cloudfra/certtool)

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
