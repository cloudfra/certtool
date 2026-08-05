# Certificate Specs

The `--spec` flag accepts a YAML file that describes one or more certificates to generate as a tree. Each node in the tree defines a certificate; child nodes are signed by their parent.

## Spec Format

Each node supports the following fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `commonName` | string | yes | Subject common name (CN) |
| `certificateAuthority` | bool | no | Whether this certificate is a CA |
| `codeSigning` | bool | no | Generate a code signing certificate (produces a `.pfx` bundle) |
| `target` | string | no | Platform profile for code signing (e.g. `windows7`, `windows10`, `windows11`, `linux`) |
| `pfxPassword` | string | no | Password for the `.pfx` file; empty means no password |
| `keyType` | string | no | Key algorithm and size (e.g. `RSA-2048`, `RSA-4096`, `ECDSA-256`). Omit for code signing nodes to use the target profile default |
| `validity` | string | no | Duration (e.g. `8760h` for 1 year, `87600h` for 10 years) |
| `organization` | string | no | Subject organization (O) |
| `country` | string | no | Subject country (C) |
| `hostnames` | list | no | SANs added to the certificate |
| `ports` | list | no | Ports for SAN URI entries |
| `filename` | string | no | Output filename base (without extension); defaults to a slug of the CN path |
| `children` | list | no | Child certificates signed by this node |

A spec must have at least one node. Multiple top-level nodes are allowed for disjoint configurations (e.g. a TLS hierarchy and a separate code signing certificate). Any node with `children` must also be a CA.

## Quick Chain

For a simple linear chain (root CA, optional intermediates, leaf), use `--chain N` instead of writing a spec file:

```sh
# Root CA + leaf (2 certificates)
certtool --chain 2 --output-dir certs/

# Root CA + 1 intermediate + leaf (3 certificates)
certtool --chain 3 --output-dir certs/
```

## Examples

### Single CA with One Leaf

The simplest spec: a root CA that signs a single leaf certificate.

```yaml
- commonName: "Simple Root CA"
  certificateAuthority: true
  keyType: "RSA-2048"
  validity: "87600h"
  children:
    - commonName: "app.example.com"
      hostnames:
        - app.example.com
        - localhost
      validity: "8760h"
```

See [`examples/simple-chain.yaml`](../examples/simple-chain.yaml).

```sh
certtool --spec examples/simple-chain.yaml --output-dir certs/
```

This produces four files:

```
certs/simple-root-ca.cert
certs/simple-root-ca.key
certs/simple-root-ca-app-example-com.cert
certs/simple-root-ca-app-example-com.key
```

### Three-Tier Chain (Root, Intermediate, Leaf)

A production-style setup with an intermediate CA between the root and the leaf. The leaf uses a different key algorithm (ECDSA) than the CA chain (RSA).

```yaml
- commonName: "Acme Root CA"
  certificateAuthority: true
  keyType: "RSA-4096"
  validity: "87600h"
  organization: "Acme Corp"
  country: "US"
  children:
    - commonName: "Acme Intermediate CA"
      certificateAuthority: true
      keyType: "RSA-4096"
      validity: "43800h"
      children:
        - commonName: "api.acme.com"
          keyType: "ECDSA-256"
          validity: "8760h"
          hostnames:
            - api.acme.com
            - internal.acme.com
          ports: [443, 8443]
```

See [`examples/three-tier.yaml`](../examples/three-tier.yaml).

```sh
certtool --spec examples/three-tier.yaml --output-dir certs/
```

### Multiple Leaves from One CA

A single root CA signing several leaf certificates, useful for microservice or local development environments. The `filename` field overrides the default slug-based naming.

```yaml
- commonName: "Dev Root CA"
  certificateAuthority: true
  keyType: "ECDSA-256"
  validity: "87600h"
  organization: "DevTeam"
  filename: "dev-root-ca"
  children:
    - commonName: "frontend.dev.local"
      hostnames:
        - frontend.dev.local
        - localhost
      ports: [3000, 8080]
      filename: "frontend"
    - commonName: "backend.dev.local"
      hostnames:
        - backend.dev.local
        - localhost
      ports: [8443]
      filename: "backend"
```

See [`examples/multi-leaf.yaml`](../examples/multi-leaf.yaml).

```sh
certtool --spec examples/multi-leaf.yaml --output-dir certs/
```

This produces:

```
certs/dev-root-ca.cert
certs/dev-root-ca.key
certs/frontend.cert
certs/frontend.key
certs/backend.cert
certs/backend.key
```

### Single Certificate (No Hierarchy)

A spec with one node and no children generates a single self-signed certificate:

```yaml
- commonName: "standalone.example.com"
  certificateAuthority: true
  keyType: "ECDSA-256"
  validity: "8760h"
  hostnames:
    - standalone.example.com
    - localhost
```

```sh
certtool --spec standalone.yaml --output-dir certs/
```

### Code Signing Certificate

A single code signing certificate for Windows binary signing, producing a `.pfx` bundle:

```yaml
- commonName: "My Code Signing Certificate"
  codeSigning: true
  target: "windows10"
  pfxPassword: "changeit"
  validity: "8760h"
  organization: "Acme Corp"
  filename: "codesign"
```

```sh
certtool --spec codesign.yaml --output-dir certs/
```

This produces:

```
certs/codesign.cert
certs/codesign.key
certs/codesign.pfx
```

The `.pfx` file can be used with Windows `signtool.exe` for binary signing.

### Multiple Disjoint Configurations

A single spec can define independent certificate trees. This example generates a TLS hierarchy and a code signing certificate in one pass:

```yaml
- commonName: "Acme TLS Root CA"
  certificateAuthority: true
  keyType: "RSA-4096"
  validity: "87600h"
  organization: "Acme Corp"
  filename: "tls-root-ca"
  children:
    - commonName: "api.acme.com"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - api.acme.com
      filename: "api-server"

- commonName: "Acme Code Signing"
  codeSigning: true
  target: "windows10"
  validity: "8760h"
  organization: "Acme Corp"
  filename: "codesign"
```

```sh
certtool --spec acme-all.yaml --output-dir certs/
```

This produces TLS certificates (`.cert`/`.key`) for the CA and API server, plus a code signing bundle (`.cert`/`.key`/`.pfx`).

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
      ports: [636, 3269]
      filename: "dc01"
    - commonName: "dc02.contoso.local"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - dc02.contoso.local
        - contoso.local
        - ldap.contoso.local
      ports: [636, 3269]
      filename: "dc02"
```

```sh
certtool --spec ad-ldaps.yaml --output-dir certs/
```

Import `contoso-root-ca.cert` into the Trusted Root store on domain members, and install each DC's cert/key pair on the corresponding server.

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
      ports: [6443]
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
          ports: [2379, 2380]
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

```sh
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
      ports: [8443]
      filename: "api-gateway"
    - commonName: "user-service"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - user-service
        - user-service.platform.svc.cluster.local
      ports: [8443]
      filename: "user-service"
    - commonName: "order-service"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - order-service
        - order-service.platform.svc.cluster.local
      ports: [8443]
      filename: "order-service"
    - commonName: "payment-service"
      keyType: "ECDSA-256"
      validity: "8760h"
      hostnames:
        - payment-service
        - payment-service.platform.svc.cluster.local
      ports: [8443]
      filename: "payment-service"
```

```sh
certtool --spec mtls-services.yaml --output-dir certs/
```

Each service loads its own cert/key and the shared `platform-ca.cert` as the trusted root for verifying peers.

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
      ports: [5432]
      filename: "postgres"
    - commonName: "redis.internal"
      keyType: "RSA-2048"
      validity: "8760h"
      hostnames:
        - redis.internal
        - redis-sentinel.internal
        - localhost
      ports: [6379, 26379]
      filename: "redis"
```

```sh
certtool --spec infra-tls.yaml --output-dir /etc/ssl/infra/
```

Configure PostgreSQL with `ssl_cert_file` / `ssl_key_file` and Redis with `tls-cert-file` / `tls-key-file`, then distribute `infra-ca.cert` to application servers.

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
      ports: [443, 1194]
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

```sh
certtool --spec vpn.yaml --output-dir /etc/openvpn/pki/
```
