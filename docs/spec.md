# Certificate Spec

The `--spec` flag lets you define an entire certificate hierarchy in a single YAML file and generate all certificates in one pass.

```bash
certtool --spec certs.yaml --output-dir ./certs
```

## Spec Format

A spec file is a YAML list of `CertificateSpec` entries. Each entry defines one certificate. Entries with `children` form a tree where the parent signs all child certificates.

### Fields

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `commonName` | string | yes | Subject common name (CN). |
| `certificateAuthority` | bool | | Must be `true` when the spec has `children`. |
| `codeSigning` | bool | | Generate a code signing certificate instead of TLS. |
| `target` | string | | Platform profile for code signing (`windows7`, `windows10`, `windows11`, `linux`). Default: `windows10`. |
| `pfxPassword` | string | | Password for the `.pfx` bundle (code signing only). |
| `keyType` | string | | Key algorithm and size (`RSA-2048`, `RSA-4096`, `ECDSA-256`, `ECDSA-384`). |
| `validity` | string | | Go duration (e.g. `8760h` for 1 year, `87600h` for 10 years). Default: `8760h`. |
| `organization` | string | | Subject organization (O). |
| `organizationalUnit` | string | | Subject organizational unit (OU). |
| `country` | string | | Subject country (C). |
| `locality` | string | | Subject locality (L). |
| `province` | string | | Subject state/province (ST). |
| `hostnames` | list | | DNS names and IPs added as SANs. |
| `ports` | list | | Ports applied to each hostname without an explicit port. |
| `filename` | string | | Override the output filename (without extension). |
| `children` | list | | Child specs signed by this certificate. |

### Output filenames

By default, filenames are derived from the slugified common name path through the tree. For example, a leaf with CN `app.example.com` under a root with CN `Root CA` produces `root-ca-app-example-com.cert` and `root-ca-app-example-com.key`. Use the `filename` field to override.

## Examples

All example spec files are in [`pkg/certtool/testdata/`](../pkg/certtool/testdata/) and are used by the test suite.

### Simple CA chain

A root CA with a single leaf certificate for TLS.

```yaml
# testdata/simple-chain.yaml
- commonName: "Root CA"
  certificateAuthority: true
  keyType: "ECDSA-256"
  validity: "87600h"
  children:
    - commonName: "app.example.com"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - app.example.com
        - localhost
```

```bash
certtool --spec simple-chain.yaml --output-dir ./certs
# Produces:
#   certs/root-ca.cert
#   certs/root-ca.key
#   certs/root-ca-app-example-com.cert
#   certs/root-ca-app-example-com.key
```

### Multiple services

A root CA issuing certificates for multiple services with custom filenames.

```yaml
# testdata/multi-service.yaml
- commonName: "Acme Corp Root CA"
  certificateAuthority: true
  keyType: "RSA-2048"
  validity: "87600h"
  organization: "Acme Corp"
  country: "US"
  children:
    - commonName: "api.acme.dev"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - api.acme.dev
        - api.acme.local
      ports: [443, 8443]
      filename: "api"
    - commonName: "web.acme.dev"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - web.acme.dev
      filename: "web"
    - commonName: "grpc.acme.dev"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - grpc.acme.dev
      filename: "grpc"
```

```bash
certtool --spec multi-service.yaml --output-dir ./certs
# Produces:
#   certs/acme-corp-root-ca.cert, certs/acme-corp-root-ca.key
#   certs/api.cert, certs/api.key
#   certs/web.cert, certs/web.key
#   certs/grpc.cert, certs/grpc.key
```

### Intermediate CA

A three-level hierarchy: root CA, intermediate CA, and leaf certificates.

```yaml
# testdata/intermediate-ca.yaml
- commonName: "Root CA"
  certificateAuthority: true
  keyType: "RSA-4096"
  validity: "87600h"
  children:
    - commonName: "Intermediate CA"
      certificateAuthority: true
      keyType: "RSA-2048"
      validity: "43800h"
      children:
        - commonName: "server.internal"
          keyType: "RSA-2048"
          validity: "8760h"
          hostnames:
            - server.internal
          filename: "server"
        - commonName: "db.internal"
          keyType: "RSA-2048"
          validity: "8760h"
          hostnames:
            - db.internal
          filename: "db"
```

```bash
certtool --spec intermediate-ca.yaml --output-dir ./certs
# Produces:
#   certs/root-ca.cert, certs/root-ca.key
#   certs/root-ca-intermediate-ca.cert, certs/root-ca-intermediate-ca.key
#   certs/server.cert, certs/server.key
#   certs/db.cert, certs/db.key
```

### Code signing

A code signing certificate for Windows 10/11.

```yaml
# testdata/code-signing.yaml
- commonName: "Acme Code Signing"
  codeSigning: true
  target: "windows10"
  organization: "Acme Corp"
  validity: "8760h"
  filename: "codesign"
```

```bash
certtool --spec code-signing.yaml --output-dir ./certs
# Produces:
#   certs/codesign.cert
#   certs/codesign.key
#   certs/codesign.pfx
```

### Mixed roots

Multiple independent trees in one file: a TLS hierarchy and a code signing certificate.

```yaml
# testdata/mixed-roots.yaml
- commonName: "TLS Root CA"
  certificateAuthority: true
  keyType: "ECDSA-256"
  validity: "87600h"
  children:
    - commonName: "frontend.example.com"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - frontend.example.com
      filename: "frontend"
    - commonName: "backend.example.com"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - backend.example.com
      filename: "backend"
- commonName: "Release Signing"
  codeSigning: true
  target: "windows10"
  validity: "8760h"
  filename: "release-sign"
```

```bash
certtool --spec mixed-roots.yaml --output-dir ./certs
# Produces:
#   certs/tls-root-ca.cert, certs/tls-root-ca.key
#   certs/frontend.cert, certs/frontend.key
#   certs/backend.cert, certs/backend.key
#   certs/release-sign.cert, certs/release-sign.key, certs/release-sign.pfx
```
