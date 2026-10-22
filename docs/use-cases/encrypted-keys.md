# Encrypted private keys

Some keys have to exist as files: a server's TLS key, or the keys a spec generates in bulk. `--encrypt-to` encrypts every private key and `.pfx` file certtool writes with [age](https://age-encryption.org), so reading one takes a YubiKey, or another age key, instead of a password that has to be stored next to it.

Certificates (`.crt`) are public and stay unencrypted. Encrypted files get an `.age` suffix: `app.key.age`, `codesign.pfx.age`.

A key that never leaves the YubiKey is safer still, because an encrypted key is decrypted wherever it is used. Use a [YubiKey root CA](yubikey-root-ca.md) for keys that only sign.

## 1. Create an age key on the YubiKey

[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) creates the key, in one of the retired slots 82 through 95:

```bash
age-plugin-yubikey --generate --pin-policy once --touch-policy always
age-plugin-yubikey --list   # prints the recipient again: age1yubikey1... (newer releases may print age1tag1...)
```

Make a second recipient for recovery, because a key encrypted only to one YubiKey is lost with it. Keep `backup.txt` offline:

```bash
age-keygen -o backup.txt    # prints the backup's recipient: age1...
```

## 2. Generate encrypted keys

Pass every recipient to `--encrypt-to`. Encrypting needs only the recipients, not the YubiKey or the plugin, so a CI job can do it:

```bash
certtool --spec certs.yaml --output-dir certs --encrypt-to age1yubikey1...,age1...
certtool --common-name api.example.com --hostnames api.example.com --encrypt-to age1yubikey1...   # writes app.crt and app.key.age
```

`--encrypt-to` accepts X25519 (`age1...`), post-quantum (`age1pq1...`), tagged hardware (`age1tag1...`), and age-plugin-yubikey (`age1yubikey1...`) recipients. age refuses to mix post-quantum recipients with others.

## 3. Read encrypted keys back

certtool reads private keys when signing with `--parent-private-key`, and when `--spec` or `--chain` reuses the certificates already in `--output-dir`. To decrypt them, give it an identity:

- `--age-yubikey` decrypts with the YubiKey. certtool finds the key among slots 82 through 95 and 9d. It needs the PIN from `CERTTOOL_YUBIKEY_PIN`, and a touch if the key's touch policy asks for one. Select a YubiKey with `--yubikey-serial` when more than one is connected.
- `--age-identity-file backup.txt` decrypts with age identities in a file.
- The `CERTTOOL_AGE_IDENTITY` environment variable can hold identities too, for CI.

```bash
# Add a certificate to an existing spec: the CAs' keys are decrypted to sign it.
# CERTTOOL_YUBIKEY_PIN must hold the YubiKey PIN.
certtool --spec certs.yaml --output-dir certs --encrypt-to age1yubikey1...,age1... --age-yubikey

# Sign with an encrypted issuing CA
certtool --common-name api.example.com --hostnames api.example.com \
  --parent-public-certificate issuing-ca.crt --parent-private-key issuing-ca.key.age --age-yubikey
```

Without an identity, certtool stops and names the encrypted file. `--overwrite` regenerates everything instead, and removes the old form of each key, so a directory never holds both `app.key` and `app.key.age`.

## 4. Deploy a key

Decrypt the key on the machine that uses it, with the age CLI and the plugin, or with the backup identity:

```bash
age-plugin-yubikey --identity > yubikey-identity.txt   # not secret: it only names the YubiKey and slot
age --decrypt -i yubikey-identity.txt -o app.key app.key.age
age --decrypt -i backup.txt -o app.key app.key.age
```

For servers that start unattended, encrypt each key to the server's own age key as well as to the YubiKey: `age-keygen` on the server, and add its recipient to `--encrypt-to`. The server decrypts its key at startup, and the YubiKey can always recover it.
