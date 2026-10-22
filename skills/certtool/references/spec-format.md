# certtool spec format

A spec is a YAML list of certificates. An entry with `children` is a CA that signs each child. Generate with `certtool --spec certs.yaml --output-dir certs`. To get a starting file, run `certtool --chain 1,2,1 --organization Acme --export-spec certs.yaml`.

## Fields

| Field | Description |
| ----- | ----------- |
| `commonName` | Required. Subject common name. |
| `certificateAuthority` | Must be `true` on an entry with `children`. |
| `children` | Certificates signed by this entry. |
| `maxPathLen` | CAs only. CAs allowed below this one; defaults to the depth of CAs the spec puts below it, `-1` for no limit. |
| `permittedDNSDomains`, `permittedIPRanges` | CAs only. Name constraints: the DNS domains and CIDR ranges certificates below the CA may use. |
| `keyType` | `RSA-2048`, `RSA-4096`, `ECDSA-256`, `ECDSA-384`. |
| `validity` | Go duration, for example `8760h`. Default `8760h`. |
| `hostnames` | DNS names and IP addresses added as SANs. |
| `organization`, `organizationalUnit`, `country`, `locality`, `province` | Subject fields. |
| `codeSigning` | `true` for a code signing certificate. Keep these at the top level of the spec: a child must have the same `codeSigning` value as its CA, so a TLS CA cannot hold code signing children. |
| `target` | Code signing profile: `windows7`, `windows10` (default), `windows11`, `linux`. |
| `pfxPasswordEnv` | Name of an environment variable holding the `.pfx` password (code signing only). Use this instead of `pfxPassword`, which stores the password in plain text. |
| `filename` | Output file name without extension. Directories, `..`, and absolute paths are rejected. |

## Running again

Running the same spec again reuses certificates whose `.crt` and `.key` files already exist in `--output-dir`, so new entries extend the hierarchy under the existing CAs. A reused certificate must match the spec's common name and CA flag, be unexpired, and be signed by its parent; otherwise certtool stops and names the files to delete. `--overwrite` regenerates everything.

## Output names

Without `filename`, each file is named after the slugified common names on the path from the root, so a leaf `app.example.com` under `Root CA` becomes `root-ca-app-example-com.crt` and `.key`. Code signing entries for Windows targets also get a `.pfx`. Set `filename` on every entry when other tools need stable paths.

## Example

```yaml
- commonName: "Platform CA"
  certificateAuthority: true
  organization: "Acme"
  keyType: "ECDSA-384"
  validity: "43800h"
  filename: "platform-ca"
  children:
    - commonName: "api.internal.example.com"
      keyType: "ECDSA-256"
      validity: "2160h"
      hostnames:
        - api.internal.example.com
        - 10.0.0.12
      filename: "api"
    - commonName: "billing-client"
      keyType: "ECDSA-256"
      validity: "2160h"
      filename: "billing-client"
- commonName: "Acme Release Signing"
  codeSigning: true
  target: "windows10"
  organization: "Acme"
  filename: "release-sign"
```

This writes `platform-ca`, `api`, and `billing-client` as `.crt` and `.key` files, plus `release-sign.crt`, `release-sign.key`, and `release-sign.pfx`.

## With a YubiKey

`certtool --yubikey --spec certs.yaml --output-dir certs` signs every top-level entry with the root CA on the YubiKey instead of self-signing it. Leave the root out of the spec, because it already lives on the YubiKey. Code signing entries may then be top-level entries signed by the YubiKey root.

More examples (Kubernetes, LDAPS, mTLS, databases, VPN): <https://github.com/cloudfra/certtool/blob/main/docs/spec.md>.
