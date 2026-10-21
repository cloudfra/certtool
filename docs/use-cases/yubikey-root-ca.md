# YubiKey root CA

Keep your root CA's private key in the PIV smart card applet of a YubiKey. A key in the YubiKey cannot be read off it, so it cannot be copied. Every signature needs the YubiKey to be plugged in, the PIN, and, by default, a touch.

Both scenarios below build the same hierarchy. The YubiKey signs one intermediate CA, and the intermediate signs the day-to-day leaf certificates, so the YubiKey stays in a drawer most of the time:

```text
YubiKey slot 9c: Acme Root CA            10 years, signs only when the YubiKey is present
└── Acme Issuing CA (issuing-ca.key)      3 years, key in a file
    ├── api.internal.example.com          server certificate, 90 days
    ├── web.internal.example.com          server certificate, 90 days
    └── billing-client                    client certificate, 90 days
```

* [Scenario 1: certtool generates the root on the YubiKey](#scenario-1-certtool-generates-the-root). Start here if the YubiKey has no CA yet.
* [Scenario 2: the YubiKey already holds a CA](#scenario-2-the-yubikey-already-holds-a-ca). Start here if a root CA is already in a slot, whether certtool, ykman, or another tool put it there.
* [Providing the PIN](#providing-the-pin). Needed by both scenarios.
* [YAML spec](#yaml-spec-the-intermediate-and-its-leaves-in-one-command). Either scenario, with the intermediate and leaves described in one file.

`--yubikey` only signs with a root CA that is already on the YubiKey. It never creates one by itself, and fails with `there is no certificate in the slot` if the slot is empty.

## Requirements

| Platform | YubiKey support |
| -------- | --------------- |
| Windows (386, amd64, arm64) | Yes, including the prebuilt downloads. Uses the built-in Smart Card service |
| Linux | When built with cgo: `CGO_ENABLED=1`, the pcsclite headers to build (`libpcsclite-dev` on Debian and Ubuntu), and `pcscd` running |
| macOS | When built with cgo: `CGO_ENABLED=1`. Uses the built-in PCSC framework |
| FreeBSD, OpenBSD | When built with cgo: `CGO_ENABLED=1` and pcsc-lite |
| Android, iOS, and all others | No |

The prebuilt Linux and macOS downloads are built without cgo and report an error for the `--yubikey` flags. Build certtool yourself instead:

```bash
# Debian and Ubuntu
sudo apt-get install libpcsclite-dev pcscd
CGO_ENABLED=1 go install github.com/cloudfra/certtool/cmd/certtool@latest

# macOS
CGO_ENABLED=1 go install github.com/cloudfra/certtool/cmd/certtool@latest
```

Any YubiKey with the PIV applet works (YubiKey 4, 5, and later). RSA-4096 keys need firmware 5.7 or newer.

The examples use [YubiKey Manager](https://www.yubico.com/support/download/yubikey-manager/) (`ykman`) to inspect and prepare the YubiKey. certtool itself does not need it.

## Providing the PIN

certtool runs in automation, so it never prompts for anything. Every `--yubikey` and `--yubikey-generate-root` command needs the YubiKey PIN, from the `CERTTOOL_YUBIKEY_PIN` environment variable or `--yubikey-pin`, and fails straight away without it:

```text
--yubikey needs the YubiKey PIN to sign with the key on the YubiKey: set --yubikey-pin or the CERTTOOL_YUBIKEY_PIN environment variable
```

Prefer the environment variable, because a `--yubikey-pin` value is saved in your shell history. Read it without echoing it:

```bash
read -rs -p "YubiKey PIN: " CERTTOOL_YUBIKEY_PIN && export CERTTOOL_YUBIKEY_PIN
```

```powershell
$env:CERTTOOL_YUBIKEY_PIN = Read-Host -Prompt "YubiKey PIN" -MaskInput   # PowerShell 7.1 or newer
```

In CI, set it from your secret store. The commands below assume it is set. The only thing certtool waits for is a touch of the YubiKey, which it logs as `signing with the YubiKey, touch it if it is blinking`.

## Scenario 1: certtool generates the root

### 1. Prepare the YubiKey

A new YubiKey has the factory default PIN (`123456`), PUK (`12345678`), and management key. Change all three before storing a CA key:

```bash
ykman piv info                         # check that slot 9c is empty
ykman piv access change-pin            # 6 to 8 characters
ykman piv access change-puk            # unblocks the PIN after too many wrong attempts
ykman piv access change-management-key --generate --protect
```

`--protect` stores the new management key on the YubiKey, protected by the PIN. certtool finds it there, so you only ever need the PIN.

### 2. Generate the root CA

```bash
certtool --yubikey-generate-root --common-name "Acme Root CA" --organization Acme \
  --key-type ECDSA-384 --validity 87600h --public-certificate root.crt
```

certtool generates the key in slot `9c`, self-signs a 10 year root certificate, stores it in the slot, and writes a copy to `root.crt`. Touch the YubiKey when it blinks.

* `root.crt` is the public certificate. It is not secret: distribute it to every machine that should trust your CA.
* The root is not restricted to particular uses, so it can sign TLS, client, and code signing certificates.
* Supported key types are `ECDSA-256`, `ECDSA-384`, `RSA-2048`, and `RSA-4096` (firmware 5.7 or newer).
* `--yubikey-touch-policy` sets when a touch is needed: `cached` (default; one touch covers 15 seconds of signing), `always`, or `never`.
* certtool refuses to replace a slot that already holds a certificate. Choose another slot with `--yubikey-slot` (for example `82`), or pass `--yubikey-overwrite` to destroy the old key.

Check the root:

```bash
openssl x509 -in root.crt -noout -subject -dates -ext basicConstraints,keyUsage
```

### 3. Create the intermediate CA

The YubiKey signs the intermediate. This is the only step after step 2 that needs the YubiKey:

```bash
certtool --yubikey --ca --common-name "Acme Issuing CA" --organization Acme \
  --key-type ECDSA-256 --validity 26280h \
  --public-certificate issuing-ca.crt --private-key issuing-ca.key
```

### 4. Create leaf certificates from the intermediate

The intermediate's key file signs the leaves. The YubiKey can be unplugged:

```bash
certtool --common-name api.internal.example.com --organization Acme \
  --hostnames api.internal.example.com,10.0.0.12 --key-type ECDSA-256 --validity 2160h \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate api.crt --private-key api.key

certtool --common-name web.internal.example.com --organization Acme \
  --hostnames web.internal.example.com --key-type ECDSA-256 --validity 2160h \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate web.crt --private-key web.key

certtool --common-name billing-client --organization Acme --key-type ECDSA-256 --validity 2160h \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate billing-client.crt --private-key billing-client.key
```

### 5. Verify and deploy

```bash
openssl verify -CAfile root.crt -untrusted issuing-ca.crt api.crt web.crt billing-client.crt

# Servers send the intermediate with their certificate
cat api.crt issuing-ca.crt > api-chain.crt
cat web.crt issuing-ca.crt > web-chain.crt
```

Install `root.crt` as trusted on client machines. [Private CA and mutual TLS](private-ca.md) covers trust stores, mutual TLS, and renewal.

## Scenario 2: the YubiKey already holds a CA

Use this when a slot already holds a root CA certificate and its key: one generated earlier with `--yubikey-generate-root`, possibly on another computer, or one put there with ykman or another tool. certtool doesn't care how it got there, as long as:

* the certificate is a CA certificate (basic constraints `CA:TRUE`) and, if it has a key usage, allows certificate signing,
* it is currently valid, and
* the key in the slot matches the certificate.

certtool checks all three before signing anything.

### 1. Find the CA and export its certificate

```bash
ykman piv info                                   # shows each slot's certificate subject and expiry
ykman piv certificates export 9c root.crt        # PEM by default
openssl x509 -in root.crt -noout -subject -dates -ext basicConstraints,keyUsage
```

If the CA is not in slot `9c`, export from its slot and pass the same slot to certtool in every command below, for example `--yubikey-slot 82`.

If the CA is still in files (`root-ca.crt` and `root-ca.key`) and you want to move it onto the YubiKey, import it first:

```bash
ykman piv keys import --pin-policy always --touch-policy cached 9c root-ca.key
ykman piv certificates import 9c root-ca.crt
cp root-ca.crt root.crt
```

An imported key has existed in a file, so it is only as safe as every copy of that file was. Delete the copies once the import works, or use [scenario 1](#scenario-1-certtool-generates-the-root) to make a root that never left the YubiKey.

### 2. Create the intermediate CA

```bash
certtool --yubikey --ca --common-name "Acme Issuing CA" --organization Acme \
  --key-type ECDSA-256 --validity 26280h \
  --public-certificate issuing-ca.crt --private-key issuing-ca.key
```

certtool reads the CA certificate from the slot, checks it, and signs with the PIN. If the PIN, slot, or certificate is wrong, it stops before writing any file. certtool does not shorten the intermediate to fit the root, and certificates stop verifying when the root expires. Check the root's expiry from step 1 and choose a `--validity` that ends before it.

### 3. Create leaf certificates from the intermediate

Exactly as in scenario 1, the leaves are signed with the intermediate's key file and don't need the YubiKey:

```bash
certtool --common-name api.internal.example.com --organization Acme \
  --hostnames api.internal.example.com,10.0.0.12 --key-type ECDSA-256 --validity 2160h \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate api.crt --private-key api.key

certtool --common-name web.internal.example.com --organization Acme \
  --hostnames web.internal.example.com --key-type ECDSA-256 --validity 2160h \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate web.crt --private-key web.key

certtool --common-name billing-client --organization Acme --key-type ECDSA-256 --validity 2160h \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key \
  --public-certificate billing-client.crt --private-key billing-client.key
```

### 4. Verify

```bash
openssl verify -CAfile root.crt -untrusted issuing-ca.crt api.crt web.crt billing-client.crt
```

## YAML spec: the intermediate and its leaves in one command

Both scenarios also work with a [YAML spec](../spec.md) in place of the separate commands for the intermediate and the leaves. The spec doesn't mention the YubiKey: `--yubikey` on the command line makes the YubiKey root sign each top-level entry, and each entry signs its children as usual. Here the YubiKey signs the intermediate CA and a code signing certificate, and the intermediate signs three leaves:

```yaml
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
certtool --yubikey --spec certs.yaml --output-dir certs

# Use another slot or YubiKey with the same flags as the other commands
certtool --yubikey --yubikey-slot 82 --yubikey-serial 12345678 --spec certs.yaml --output-dir certs
```

The YubiKey signs twice, once for each top-level entry. It writes:

```text
certs/issuing-ca.cert, certs/issuing-ca.key           signed by the YubiKey root
certs/api.cert, certs/api.key                          signed by Acme Issuing CA
certs/web.cert, certs/web.key                          signed by Acme Issuing CA
certs/billing-client.cert, certs/billing-client.key    signed by Acme Issuing CA
certs/release-sign.cert, certs/release-sign.key, certs/release-sign.pfx   signed by the YubiKey root
```

Verify the result against the root:

```bash
openssl verify -CAfile root.crt -untrusted certs/issuing-ca.cert \
  certs/api.cert certs/web.cert certs/billing-client.cert certs/release-sign.cert
```

Without `--yubikey`, the same spec makes `Acme Issuing CA` and `Acme Release Signing` self-signed, which is handy for trying it out first. This file is [`pkg/certtool/testdata/yubikey-intermediate.yaml`](../../pkg/certtool/testdata/yubikey-intermediate.yaml), and the test suite signs it with a simulated YubiKey.

`--chain` also works with `--yubikey`, but it names its top layer as a root (`Acme Root CA`) even though the YubiKey signed it. Use a spec to name the certificates under a YubiKey root accurately.

## Sign certificates directly with the YubiKey

`--yubikey` replaces `--parent-public-certificate` and `--parent-private-key` in any command. Intermediates made with `--ca` are limited to TLS, so sign code signing certificates directly with the YubiKey root:

```bash
certtool --yubikey --code-sign --common-name "Acme Release Signing" --organization Acme \
  --pfx-output release.pfx --pfx-password "change-me"
```

See [Code signing](code-signing.md) for using `release.pfx`.

## Automation

certtool never prompts, so the commands in this guide run unchanged in scripts and CI once `CERTTOOL_YUBIKEY_PIN` is set (see [Providing the PIN](#providing-the-pin)). For example, in a GitHub Actions job on a self-hosted runner with the YubiKey attached:

```yaml
- name: Sign the issuing CA
  env:
    CERTTOOL_YUBIKEY_PIN: ${{ secrets.YUBIKEY_PIN }}
  run: certtool --yubikey --ca --common-name "Acme Issuing CA" --public-certificate issuing-ca.crt --private-key issuing-ca.key
```

A root generated with the default `cached` touch policy still needs a touch. For signing with no one present, generate the root with `--yubikey-touch-policy never`. Then anyone with the YubiKey and the PIN can sign, so keep both protected.

With several YubiKeys connected, choose one with `--yubikey-serial`. List the serial numbers with `ykman list --serials`.

## Backups and replacement

The key cannot be exported, so a lost or broken YubiKey means a lost root. Plan for it:

* Generate a second root on a second YubiKey, store that YubiKey somewhere safe, and distribute both `root.crt` files. Either root can sign a replacement intermediate.
* Or rely on an intermediate with a long validity, and generate a new root and distribute it if the YubiKey is lost.

If an intermediate's key leaks, the YubiKey root is unaffected: sign a new intermediate, reissue its leaves, and remove the old intermediate from your servers.

To replace a root on the same YubiKey, run scenario 1, step 2 again with `--yubikey-overwrite`. Certificates signed by the old root stop verifying once machines trust only the new one.

## Troubleshooting

Every YubiKey error names the YubiKey, its firmware, and the slot, and says how to fix the problem when certtool recognizes it.

| Error contains | Fix |
| -------------- | --- |
| `does not support YubiKeys` | Use a Windows build, or build certtool with `CGO_ENABLED=1` (see [Requirements](#requirements)) |
| `cannot list smart card readers` | Start the smart card service: `sudo systemctl enable --now pcscd.socket` on Linux, the Smart Card (`SCardSvr`) service on Windows |
| `no YubiKey is connected` | Plug it in. If it is, enable its smart card interface: `ykman config usb --enable CCID` |
| `it may be in use by another program` | Close the program holding it, for example `gpgconf --kill scdaemon`, ykman, or Yubico Authenticator |
| `more than one YubiKey is connected` | Choose one with `--yubikey-serial` |
| `there is no certificate in the slot` | Generate a root there ([scenario 1](#scenario-1-certtool-generates-the-root)) or check `--yubikey-slot` |
| `is not a CA certificate` | The slot holds an ordinary certificate. Use the slot that holds your CA, or generate a root |
| `does not match the certificate` | The slot's key was replaced without its certificate. Import the matching certificate, or generate a new root |
| `the PIN is incorrect, N attempts remain` | Check the PIN. certtool never retries a rejected PIN by itself |
| `the PIN is blocked` | `ykman piv access unblock-pin`, using the PUK |
| `rejected the ... management key` | Pass the management key with `--yubikey-management-key` or `CERTTOOL_YUBIKEY_MANAGEMENT_KEY` |
| `not touched in time` | Touch the YubiKey when it blinks |
| `the slot already holds the certificate` | Use another slot, or `--yubikey-overwrite` to destroy the old key |
| `need YubiKey firmware` | Use a key type your firmware supports, such as `ECDSA-384` |
| `expired` or `is not valid until` | Replace the root (see [Backups and replacement](#backups-and-replacement)), or check the computer's clock |
| `needs the YubiKey PIN` | Set `CERTTOOL_YUBIKEY_PIN` or `--yubikey-pin`. certtool never prompts for it |
