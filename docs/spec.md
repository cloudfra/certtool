# Certificate Spec

The `--spec` flag lets you define an entire certificate hierarchy in a single YAML file and generate all certificates in one pass.

```bash
certtool --spec certs.yaml --output-dir ./certs

# Sign the top-level certificates with a root CA on a YubiKey
certtool --yubikey --spec certs.yaml --output-dir ./certs
```

## Spec Format

A spec file is a YAML list of `CertificateSpec` entries. Each entry defines one certificate. Entries with `children` form a tree where the parent signs all child certificates.

### Fields

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `commonName` | string | yes | Subject common name (CN). |
| `certificateAuthority` | bool | | Must be `true` when the spec has `children`. |
| `codeSigning` | bool | | Generate a code signing certificate instead of TLS. A child must have the same value as its parent CA, so put code signing certificates at the top level. |
| `target` | string | | Platform profile for code signing (`windows7`, `windows10`, `windows11`, `linux`). Default: `windows10`. |
| `pfxPassword` | string | | Password for the `.pfx` bundle (code signing only). Stored in plain text, so certtool warns about it; prefer `pfxPasswordEnv`. |
| `pfxPasswordEnv` | string | | Name of an environment variable that holds the `.pfx` password. It must be set when the spec is generated. `--export-spec` writes this instead of a password. |
| `keyType` | string | | Key algorithm and size (`RSA-2048`, `RSA-4096`, `ECDSA-256`, `ECDSA-384`). |
| `validity` | string | | Go duration (e.g. `8760h` for 1 year, `87600h` for 10 years). Default: `8760h`. |
| `organization` | string | | Subject organization (O). |
| `organizationalUnit` | string | | Subject organizational unit (OU). |
| `country` | string | | Subject country (C). |
| `locality` | string | | Subject locality (L). |
| `province` | string | | Subject state/province (ST). |
| `hostnames` | list | | DNS names and IPs added as SANs. A port suffix is removed; a wildcard must be the leftmost label with at least two labels after it (`*.example.com`). |
| `filename` | string | | Override the output filename (without extension). Must be a plain file name: directories, `..`, and absolute paths are rejected so every file stays in `--output-dir`. |
| `maxPathLen` | int | | CAs only. How many CAs may sit below this one. Default: the number of CA levels below it in the spec, so `--chain 1,2,3` gives the root 1 and the intermediates 0. `-1` means no limit. |
| `permittedDNSDomains` | list | | CAs only. DNS domains that certificates below the CA may use, as critical name constraints. `example.com` permits it and its subdomains; `.example.com` only its subdomains. |
| `permittedIPRanges` | list | | CAs only. IP ranges in CIDR notation, such as `10.0.0.0/8`, that certificates below the CA may use. |
| `children` | list | | Child specs signed by this certificate. |

### Output filenames

By default, filenames are derived from the slugified common name path through the tree. For example, a leaf with CN `app.example.com` under a root with CN `Root CA` produces `root-ca-app-example-com.crt` and `root-ca-app-example-com.key`. Use the `filename` field to override.

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
#   certs/root-ca.crt
#   certs/root-ca.key
#   certs/root-ca-app-example-com.crt
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
#   certs/acme-corp-root-ca.crt, certs/acme-corp-root-ca.key
#   certs/api.crt, certs/api.key
#   certs/web.crt, certs/web.key
#   certs/grpc.crt, certs/grpc.key
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
#   certs/root-ca.crt, certs/root-ca.key
#   certs/root-ca-intermediate-ca.crt, certs/root-ca-intermediate-ca.key
#   certs/server.crt, certs/server.key
#   certs/db.crt, certs/db.key
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
#   certs/codesign.crt
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
#   certs/tls-root-ca.crt, certs/tls-root-ca.key
#   certs/frontend.crt, certs/frontend.key
#   certs/backend.crt, certs/backend.key
#   certs/release-sign.crt, certs/release-sign.key, certs/release-sign.pfx
```

### YubiKey root CA

With `--yubikey`, the root CA on a YubiKey signs every top-level entry instead of it being self-signed. Each entry still signs its own children. The spec itself is unchanged; leave the root out, because it is already on the YubiKey.

```yaml
# testdata/yubikey-intermediate.yaml
# Generate with: certtool --yubikey --spec yubikey-intermediate.yaml --output-dir ./certs
# The YubiKey root CA signs each top-level entry: an intermediate CA, which
# signs the leaf certificates, and a code signing certificate. The root itself
# stays on the YubiKey and is not part of the spec.
- commonName: "Acme Issuing CA"
  certificateAuthority: true
  organization: "Acme"
  keyType: "ECDSA-256"
  validity: "26280h"
  filename: "issuing-ca"
  children:
    - commonName: "api.internal.example.com"
      organization: "Acme"
      keyType: "ECDSA-256"
      validity: "2160h"
      hostnames:
        - api.internal.example.com
        - 10.0.0.12
      filename: "api"
    - commonName: "web.internal.example.com"
      organization: "Acme"
      keyType: "ECDSA-256"
      validity: "2160h"
      hostnames:
        - web.internal.example.com
      filename: "web"
    - commonName: "billing-client"
      organization: "Acme"
      keyType: "ECDSA-256"
      validity: "2160h"
      filename: "billing-client"
- commonName: "Acme Release Signing"
  codeSigning: true
  organization: "Acme"
  target: "windows10"
  validity: "8760h"
  filename: "release-sign"
```

```bash
certtool --yubikey --spec yubikey-intermediate.yaml --output-dir ./certs
# Produces:
#   certs/issuing-ca.crt, certs/issuing-ca.key         (signed by the YubiKey)
#   certs/api.crt, certs/api.key                        (signed by Acme Issuing CA)
#   certs/web.crt, certs/web.key                        (signed by Acme Issuing CA)
#   certs/billing-client.crt, certs/billing-client.key  (signed by Acme Issuing CA)
#   certs/release-sign.crt, certs/release-sign.key, certs/release-sign.pfx  (signed by the YubiKey)
```

The `--yubikey-*` flags select the YubiKey, slot, and PIN. See the [YubiKey root CA guide](use-cases/yubikey-root-ca.md) for setting up the YubiKey.

## Generating a hierarchy with --chain

For simple hierarchies you do not need a spec file. `--chain` takes the number of certificates in each layer, from the root down. The last layer is the leaf certificates and every earlier layer is a CA.

| Command | Generates |
| ------- | --------- |
| `--chain 3` | 3 standalone leaf certificates (no CA) |
| `--chain 1,1` | 1 root CA and 1 leaf |
| `--chain 1,2,3` | 1 root CA, 2 intermediate CAs, and 3 leaves under each intermediate (9 certificates) |
| `--chain 1,1,1,1` | 1 root CA, 2 stacked intermediate CAs, and 1 leaf |
| `--chain 2,1,1` | 2 independent trees, each with a root CA, an intermediate CA, and a leaf |

```bash
certtool --chain 1,2,3 --common-name svc --organization Acme --output-dir ./certs
```

`--common-name` names the leaves (default: the `--organization` value) and `--organization` names the CAs. Every certificate gets a unique common name, so the output filenames never collide:

```text
certs/acme-root-ca.crt
certs/acme-root-ca-acme-intermediate-ca-1.crt
certs/acme-root-ca-acme-intermediate-ca-1-svc-1-1.crt
certs/acme-root-ca-acme-intermediate-ca-1-svc-1-2.crt
certs/acme-root-ca-acme-intermediate-ca-1-svc-1-3.crt
certs/acme-root-ca-acme-intermediate-ca-2.crt
certs/acme-root-ca-acme-intermediate-ca-2-svc-2-1.crt
...
```

Each certificate has a matching `.key` file. `--chain` and `--spec` cannot be combined; `--output-dir` applies to both.

### How certificates are named

| Rule | Example |
| ---- | ------- |
| CAs are named `<organization> Root CA` and `<organization> Intermediate CA`. | `Acme Root CA` |
| When there is more than one intermediate tier, intermediates declare their depth. With a single tier the number is left out. | `Acme Intermediate 1 CA`, `Acme Intermediate 2 CA` |
| Any layer with more than one certificate adds its 1-based position to the name. Positions from the root down are joined with dots, so the name shows the lineage. Layers with a single certificate add nothing. | `--chain 1,2,3` names the leaves `svc 1.1`, `svc 1.2`, `svc 1.3`, `svc 2.1`, and so on. |
| `--name-prefix` puts a prefix in front of every name. It is empty by default. | `--name-prefix prod` gives `prod Acme Root CA` |

If your `--common-name` would produce the same name as a generated CA (for example `--common-name "Acme Root CA"`), `certtool` reports an error instead of generating duplicate names.

```bash
# Keep two environments apart in one output directory
certtool --chain 1,1 --common-name svc --organization Acme --name-prefix prod --output-dir ./certs
certtool --chain 1,1 --common-name svc --organization Acme --name-prefix staging --output-dir ./certs
```

## Exporting a spec with --export-spec

`--export-spec <path>` writes the spec as YAML instead of generating certificates. It works with `--chain`, `--spec`, and plain flags, so you can start from a generated hierarchy and customise it.

```bash
certtool --chain 1,2,1 --common-name svc --organization Acme --export-spec certs.yaml
```

```yaml
- commonName: Acme Root CA
  certificateAuthority: true
  children:
    - commonName: Acme Intermediate CA 1
      certificateAuthority: true
      children:
        - commonName: svc 1
    - commonName: Acme Intermediate CA 2
      certificateAuthority: true
      children:
        - commonName: svc 2
```

Edit the file, for example to add `hostnames` to the leaves, then generate the certificates from it:

```bash
certtool --spec certs.yaml --output-dir ./certs
```

Exporting the flags of a single certificate is a quick way to see the field names:

```bash
certtool --hostnames example.com --export-spec single.yaml
```

```yaml
- commonName: cloudfra
  keyType: RSA-2048
  validity: 8760h0m0s
  organization: cloudfra
  organizationalUnit: gows
  country: US
  locality: Seattle
  province: WA
  hostnames:
    - example.com
```

## Real-World Use Cases

### Active Directory / LDAPS

Active Directory Domain Controllers require certificates for LDAP over TLS (LDAPS). In production these come from an enterprise CA like AD CS, but for lab environments or testing you can generate them with a spec. Each DC needs a certificate with its FQDN in the SANs.

```yaml
- commonName: "Contoso Enterprise Root CA"
  certificateAuthority: true
  keyType: "RSA-4096"
  validity: "87600h"
  organization: "Contoso Ltd"
  country: "US"
  filename: "contoso-root-ca"
  children:
    - commonName: "dc01.contoso.local"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - dc01.contoso.local
        - contoso.local
        - ldap.contoso.local
      filename: "dc01"
    - commonName: "dc02.contoso.local"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - dc02.contoso.local
        - contoso.local
        - ldap.contoso.local
      filename: "dc02"
```

```bash
certtool --spec ad-ldaps.yaml --output-dir certs/
```

Import `contoso-root-ca.crt` into the Trusted Root store on domain members, and install each DC's cert/key pair on the corresponding server.

### Kubernetes Cluster

A Kubernetes cluster uses TLS throughout: the API server, etcd, kubelets, and the front proxy each need certificates from a shared root. This mirrors what `kubeadm` generates, useful for testing or custom cluster bootstrapping.

```yaml
- commonName: "kubernetes-ca"
  certificateAuthority: true
  keyType: "RSA-4096"
  validity: "87600h"
  organization: "kubernetes"
  filename: "ca"
  children:
    - commonName: "kube-apiserver"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - kubernetes
        - kubernetes.default
        - kubernetes.default.svc
        - kubernetes.default.svc.cluster.local
        - 10.96.0.1
        - 192.168.1.100
      filename: "apiserver"
    - commonName: "kube-apiserver-kubelet-client"
      keyType: "RSA-2048"
      validity: "8760h"
      organization: "system:masters"
      filename: "apiserver-kubelet-client"
    - commonName: "etcd-ca"
      certificateAuthority: true
      keyType: "RSA-4096"
      validity: "87600h"
      filename: "etcd-ca"
      children:
        - commonName: "kube-etcd"
          keyType: "RSA-2048"
          validity: "8760h"
          hostnames:
            - localhost
            - 127.0.0.1
            - 192.168.1.100
          filename: "etcd-server"
        - commonName: "kube-etcd-peer"
          keyType: "RSA-2048"
          validity: "8760h"
          hostnames:
            - localhost
            - 127.0.0.1
            - 192.168.1.100
          filename: "etcd-peer"
```

```bash
certtool --spec k8s-cluster.yaml --output-dir /etc/kubernetes/pki/
```

### Mutual TLS (mTLS) for Microservices

Service-to-service authentication using mutual TLS. Both sides present certificates from the same CA, so each service can verify the other.

```yaml
- commonName: "Platform Services CA"
  certificateAuthority: true
  keyType: "ECDSA-256"
  validity: "43800h"
  organization: "platform"
  filename: "platform-ca"
  children:
    - commonName: "api-gateway"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - api-gateway
        - api-gateway.platform.svc.cluster.local
      filename: "api-gateway"
    - commonName: "user-service"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - user-service
        - user-service.platform.svc.cluster.local
      filename: "user-service"
    - commonName: "order-service"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - order-service
        - order-service.platform.svc.cluster.local
      filename: "order-service"
    - commonName: "payment-service"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - payment-service
        - payment-service.platform.svc.cluster.local
      filename: "payment-service"
```

```bash
certtool --spec mtls-services.yaml --output-dir certs/
```

Each service loads its own cert/key and the shared `platform-ca.crt` as the trusted root for verifying peers.

### PostgreSQL and Redis with TLS

Database and cache servers that accept TLS connections, with a shared CA so application servers can verify them.

```yaml
- commonName: "Infrastructure CA"
  certificateAuthority: true
  keyType: "RSA-4096"
  validity: "87600h"
  organization: "infra"
  filename: "infra-ca"
  children:
    - commonName: "postgres.internal"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - postgres.internal
        - db-primary.internal
        - db-replica.internal
        - localhost
      filename: "postgres"
    - commonName: "redis.internal"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - redis.internal
        - redis-sentinel.internal
        - localhost
      filename: "redis"
```

```bash
certtool --spec infra-tls.yaml --output-dir /etc/ssl/infra/
```

Configure PostgreSQL with `ssl_cert_file` / `ssl_key_file` and Redis with `tls-cert-file` / `tls-key-file`, then distribute `infra-ca.crt` to application servers.

### VPN / IPSec Gateway

A VPN root CA that signs gateway and client certificates for site-to-site or remote-access VPN tunnels.

```yaml
- commonName: "VPN Root CA"
  certificateAuthority: true
  keyType: "RSA-4096"
  validity: "87600h"
  organization: "Network Operations"
  filename: "vpn-ca"
  children:
    - commonName: "vpn-gateway.example.com"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - vpn-gateway.example.com
        - vpn.example.com
        - 203.0.113.10
      filename: "vpn-gateway"
    - commonName: "site-b-gateway.example.com"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - site-b-gateway.example.com
        - 203.0.113.20
      filename: "site-b-gateway"
    - commonName: "remote-user-alice"
      keyType: "RSA-2048"
      validity: "4380h"
      filename: "client-alice"
    - commonName: "remote-user-bob"
      keyType: "RSA-2048"
      validity: "4380h"
      filename: "client-bob"
```

```bash
certtool --spec vpn.yaml --output-dir /etc/openvpn/pki/
```
