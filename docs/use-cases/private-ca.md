# Private CA and mutual TLS

Run your own certificate authority for internal services. Clients trust one root certificate, and every server and client certificate chains to it.

The layout is the usual two-tier one:

```text
Acme Root CA          10 years, kept offline, signs only the issuing CA
└── Acme Issuing CA    3 years, signs day-to-day certificates
    ├── api.internal.example.com   server certificate, 90 days
    └── billing-client             client certificate, 90 days
```

## 1. Create the root CA

```bash
certtool --ca --common-name "Acme Root CA" --organization Acme \
  --key-type ECDSA-384 --validity 87600h \
  --max-path-len 1 --permitted-dns-domains internal.example.com --permitted-ip-ranges 10.0.0.0/8 \
  --public-certificate root-ca.crt --private-key root-ca.key
```

The constraints limit the damage if a key below the root ever leaks:

- `--max-path-len 1` allows one level of CAs below the root: the issuing CA, which can only sign leaves.
- `--permitted-dns-domains` and `--permitted-ip-ranges` are name constraints. Clients reject any certificate in this hierarchy for a name outside `internal.example.com` (and its subdomains) or an address outside `10.0.0.0/8`, even though the root is trusted. certtool refuses to issue such certificates, and leaves out its usual `localhost` and `127.0.0.1` names when they fall outside the constraints.

`root-ca.key` can sign anything within those limits. After step 2, move it somewhere offline. Or keep it on a YubiKey from the start; see [YubiKey root CA](yubikey-root-ca.md).

## 2. Create the issuing CA

```bash
certtool --ca --common-name "Acme Issuing CA" --organization Acme \
  --key-type ECDSA-256 --validity 26280h --max-path-len 0 \
  --parent-public-certificate root-ca.crt --parent-private-key root-ca.key \
  --public-certificate issuing-ca.crt --private-key issuing-ca.key
```

## 3. Issue server certificates

```bash
certtool --common-name api.internal.example.com --organization Acme \
  --hostnames api.internal.example.com,10.0.0.12 --key-type ECDSA-256 --validity 2160h \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate api.crt --private-key api.key
```

Servers should send the issuing CA along with their own certificate, so clients only need the root. Most servers, such as nginx (`ssl_certificate`), take a single file with the server certificate first:

```bash
cat api.crt issuing-ca.crt > api-chain.crt
```

```powershell
Get-Content api.crt, issuing-ca.crt | Set-Content api-chain.crt
```

## 4. Issue client certificates

Every TLS certificate that certtool makes is valid for both server and client authentication, so client certificates are made the same way. Use the client's identity as the common name:

```bash
certtool --common-name billing-client --organization Acme --key-type ECDSA-256 --validity 2160h \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate billing-client.crt --private-key billing-client.key
```

## 5. Verify the chain

```bash
openssl verify -CAfile root-ca.crt -untrusted issuing-ca.crt -purpose sslserver api.crt
openssl verify -CAfile root-ca.crt -untrusted issuing-ca.crt -purpose sslclient billing-client.crt
```

Both print `OK`. On Windows, `openssl.exe` comes with Git for Windows (`C:\Program Files\Git\usr\bin\openssl.exe`).

## 6. Try mutual TLS

Like servers, clients must send the issuing CA with their certificate, or a server that trusts only the root rejects them:

```bash
cat billing-client.crt issuing-ca.crt > billing-client-chain.crt
```

Start a server that trusts only the root and requires a client certificate, then connect with and without one:

```bash
openssl s_server -accept 8443 -cert api.crt -cert_chain issuing-ca.crt -key api.key \
  -CAfile root-ca.crt -verify_return_error -Verify 1 -www

# In another terminal. --resolve points the server's name at this machine. This succeeds:
curl --resolve api.internal.example.com:8443:127.0.0.1 --cacert root-ca.crt \
  --cert billing-client-chain.crt --key billing-client.key https://api.internal.example.com:8443/

# This fails, because the server requires a client certificate:
curl --resolve api.internal.example.com:8443:127.0.0.1 --cacert root-ca.crt https://api.internal.example.com:8443/
```

## 7. Trust the root

Install only `root-ca.crt` on the machines that connect to your services. The commands are in [Local development HTTPS](local-development.md#4-trust-it-on-your-machine). For Windows machines, import it into the machine store from an administrator PowerShell:

```powershell
Import-Certificate -FilePath root-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

## Renewing

Rerun the command from step 3 or 4 before the certificate expires. Each run makes a new key. Renew the issuing CA well before its certificates' expiry dates would pass its own, because a certificate is only valid while its issuers are.

## The whole hierarchy in one command

`--chain` and `--spec` generate a root, intermediates, and leaves in one run:

```bash
certtool --chain 1,1,2 --common-name svc --organization Acme --output-dir certs
```

See the [certificate spec documentation](../spec.md) for naming, YAML specs, and more examples, including mutual TLS between microservices.

## Limitation

CA certificates made with `--ca` are limited to TLS server and client authentication, and verifiers apply that limit to everything they sign. certtool refuses to sign a code signing certificate with one, because verifiers would reject it. Use a self-signed code signing certificate or a [YubiKey root CA](yubikey-root-ca.md) instead; see [Code signing](code-signing.md).
