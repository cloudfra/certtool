# Use cases

Step-by-step command lines for common jobs. Each guide starts from nothing and ends with certificates that are in use and verified.

| Guide | When to use it |
| ----- | -------------- |
| [Local development HTTPS](local-development.md) | Serve HTTPS from your machine for `localhost` or a dev hostname, and trust it |
| [Private CA and mutual TLS](private-ca.md) | Run your own root and issuing CA for internal services, and authenticate clients with certificates |
| [Code signing](code-signing.md) | Sign Windows executables and scripts with `signtool.exe`, PowerShell, or `osslsigncode` |
| [YubiKey root CA](yubikey-root-ca.md) | Keep the root CA private key on a YubiKey so it can never be copied |
| [Encrypted private keys](encrypted-keys.md) | Encrypt the key files certtool writes to a YubiKey, so reading them needs the YubiKey instead of a password |

For whole hierarchies described in YAML, start from a [scenario](../scenarios.md): `certtool --scenario` writes a commented spec for Active Directory, Kubernetes, databases, VPNs, Wi-Fi (EAP-TLS), IoT, Kafka, Docker, iOS and Android apps, and more. The [certificate spec documentation](../spec.md) describes the format.

## Conventions

* The commands assume `certtool` is on your `PATH`. Use `./certtool` or `.\certtool.exe` if it is in the current directory.
* Multi-line commands use `\` at the end of a line, as in bash and zsh. In PowerShell, end the line with a backtick (`` ` ``) instead, or put the whole command on one line.
* Every certificate includes `localhost` and `127.0.0.1` as subject alternative names, in addition to `--hostnames`.
* The subject defaults to `C=US, ST=WA, L=Seattle, O=cloudfra, OU=gows`. Set `--organization`, `--organizational-unit`, `--country`, `--province`, and `--locality` to your own values for anything other people will see.
* Private keys are written with mode `0600`. Keep them out of source control, or encrypt them with `--encrypt-to` ([Encrypted private keys](encrypted-keys.md)).
