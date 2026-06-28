# Cert Tool

A simple and convenient tool for creating self-signed HTTPS and code signing certificates.
It can host a local directory or contents of a zip file.

```bash
# Download (linux amd64, see Downloads for other builds)
curl -o gowebserver -O -L https://github.com/cloudfra/certtool/releases/download/v1.0.0/certtool-amd64; chmod +x certtool

# Create a self-signed certificate
./certtool
```

## Features

* Zero-config required, hosts on port 80 or 8080 based on root and supports Cloud9's $PORT variable.
* HTTP and HTTPs serving
* Automatic HTTPs certificate generation
* Optional configuration by flags or YAML config file.
* Host local or HTTP served static files from:
  * Local directory (current directory is default)
  * ZIP archive
  * Tarball archive (.tar, .tar.bz2, .tar.gz, .tar.lz4, .tar.xz)
  * 7-zip
  * RAR
  * Git repository (HTTPS, SSH)
* Metrics export to Prometheus.
* Prebuild binaries for all major OSes.

## Downloads

|   OS   | Arch  | Link
|--------|-------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------
|Linux   | amd64 | `curl -O -L https://github.com/cloudfra/certtool/releases/download/v1.0.0/server-amd64`
|Linux   | arm   | `curl -O -L https://github.com/cloudfra/certtool/releases/download/v1.0.0/server-arm`
|Linux   | arm64 | `curl -O -L https://github.com/cloudfra/certtool/releases/download/v1.0.0/server-arm64`
|Windows | amd64 | `$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri "https://github.com/cloudfra/certtool/releases/download/v1.0.0/server-amd64.exe" -OutFile "server-amd64.exe" -UseBasicParsing`
|macOS   | amd64 | `curl -O -L https://github.com/cloudfra/certtool/releases/download/v1.0.0/server-amd64-darwin`
|macOS   | arm64 | `curl -O -L https://github.com/cloudfra/certtool/releases/download/v1.0.0/server-arm64-darwin`

## Docker Images

* [certtool](https://hub.docker.com/r/cloudfra/certtool/tags)

```bash
docker pull docker.io/cloudfra/certtool
```

## Build

![example workflow](https://github.com/cloudfra/certtool/actions/workflows/deploy.yml/badge.svg) [![Go Report Card](https://goreportcard.com/badge/github.com/cloudfra/certtool)](https://goreportcard.com/report/github.com/cloudfra/certtool) [![Go Reference](https://pkg.go.dev/badge/github.com/cloudfra/certtool.svg)](https://pkg.go.dev/github.com/cloudfra/certtool) [![codecov](https://codecov.io/gh/cloudfra/certtool/branch/main/graph/badge.svg)](https://codecov.io/gh/cloudfra/certtool)

Install [Go 1.24 or newer](https://golang.org/dl/).

```bash
# Clone the Codebase
git clone git@github.com:cloudfra/certtool.git
# Build the Code
make -j$(nproc)
```

## Test

```bash
make test
make bench
```
