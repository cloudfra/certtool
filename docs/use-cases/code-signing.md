# Code signing

Sign Windows executables, installers, and PowerShell scripts with a certificate from certtool. Self-signed code signing certificates are for internal software, test machines, and lab environments. Machines only accept the signature after you install the certificate as trusted.

## Windows 10 and 11

certtool reads the `.pfx` password from `CERTTOOL_PFX_PASSWORD`, so it stays out of the command line, where other users can see it, and out of your shell history. `--pfx-password` also works and takes precedence. Without a password, anyone who can read the `.pfx` can sign code with its key, so certtool logs a warning.

```bash
read -rs -p "PFX password: " CERTTOOL_PFX_PASSWORD && export CERTTOOL_PFX_PASSWORD

certtool --code-sign --common-name "Acme Internal Software" --organization Acme \
  --pfx-output codesign.pfx
```

This writes `codesign.pfx`, a PKCS#12 bundle with an ECDSA P-256 key and the certificate, encrypted with AES-256. `--target windows11` makes the same certificate.

### Sign with signtool.exe

`signtool.exe` is part of the Windows SDK.

```powershell
signtool sign /fd SHA256 /f codesign.pfx /p $env:CERTTOOL_PFX_PASSWORD app.exe

# Add a timestamp, so the signature stays valid after the certificate expires
signtool sign /fd SHA256 /f codesign.pfx /p $env:CERTTOOL_PFX_PASSWORD /tr http://timestamp.digicert.com /td SHA256 app.exe
```

### Trust the certificate on a test machine

From an administrator PowerShell, add the certificate to the trusted root and trusted publisher stores. Only the certificate is imported into these stores; keep the `.pfx` file itself off the test machine afterwards.

```powershell
$password = Read-Host -AsSecureString -Prompt "PFX password"
$cert = (Get-PfxData -FilePath codesign.pfx -Password $password).EndEntityCertificates[0]
$cer = "$env:TEMP\codesign.cer"
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

### Check the signature

```powershell
signtool verify /pa /v app.exe
Get-AuthenticodeSignature app.exe | Format-List Status, StatusMessage, SignerCertificate
```

`Status` is `Valid` once the certificate is trusted, and `UnknownError` before.

### Sign PowerShell scripts

Import the bundle into your personal store, then sign with it:

```powershell
$password = Read-Host -AsSecureString -Prompt "PFX password"
$cert = Import-PfxCertificate -FilePath codesign.pfx -CertStoreLocation Cert:\CurrentUser\My -Password $password
Set-AuthenticodeSignature -FilePath script.ps1 -Certificate $cert -HashAlgorithm SHA256
```

## Windows 7 and 8

Windows 7 cannot import AES-encrypted PKCS#12 files, and its `signtool.exe` does not support ECDSA keys. The `windows7` target uses RSA-2048 and legacy 3DES encryption:

```bash
certtool --code-sign --target windows7 --common-name "Acme Internal Software" \
  --pfx-output codesign-legacy.pfx
```

## Sign Windows binaries from Linux or macOS

[`osslsigncode`](https://github.com/mtrojnar/osslsigncode) signs Windows executables on any platform. The `linux` target writes a PEM certificate and key instead of a `.pfx` file:

```bash
certtool --code-sign --target linux --common-name "Acme Internal Software" \
  --public-certificate codesign.crt --private-key codesign.key

osslsigncode sign -certs codesign.crt -key codesign.key -n "My App" -h sha256 \
  -in app.exe -out app-signed.exe
osslsigncode verify -CAfile codesign.crt -in app-signed.exe
```

`osslsigncode` also accepts the `.pfx` from the Windows targets:

```bash
osslsigncode sign -pkcs12 codesign.pfx -pass "$CERTTOOL_PFX_PASSWORD" -h sha256 -in app.exe -out app-signed.exe
```

## Sign with a CA instead

With a self-signed certificate, every machine trusts that one certificate directly, and replacing it means updating every machine. With a CA, machines trust the CA once, and you can issue and replace code signing certificates freely.

Code signing certificates must be signed by a CA that allows code signing. CAs made with `--ca` only allow TLS, so use a [YubiKey root CA](yubikey-root-ca.md), which is not restricted:

```bash
certtool --yubikey --code-sign --common-name "Acme Release Signing" --organization Acme \
  --pfx-output release.pfx
```

Then install the YubiKey root certificate (`root.crt`), not `release.pfx`, in `Cert:\LocalMachine\Root` on the machines that run your software.
