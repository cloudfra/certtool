# Local development HTTPS

Serve HTTPS on your own machine, for `localhost` or for a development hostname such as `myapp.localhost`, without browser or `curl` warnings.

## 1. Generate the certificate

```bash
certtool --common-name myapp.localhost --hostnames myapp.localhost --key-type ECDSA-256 \
  --public-certificate dev.crt --private-key dev.key
```

`dev.crt` is valid for `myapp.localhost`, `localhost`, and `127.0.0.1` for one year. Add more names separated by commas, for example `--hostnames myapp.localhost,api.localhost,192.168.1.20`.

## 2. Use it in your server

Point your server at `dev.crt` and `dev.key`. For example:

```bash
# OpenSSL test server on port 8443
openssl s_server -accept 8443 -cert dev.crt -key dev.key -www

# Python
python3 -m http.server 8443 --bind 127.0.0.1 --tls-cert dev.crt --tls-key dev.key   # Python 3.14+
```

```go
// Go
log.Fatal(http.ListenAndServeTLS(":8443", "dev.crt", "dev.key", handler))
```

```nginx
# nginx
server {
    listen 8443 ssl;
    server_name myapp.localhost;
    ssl_certificate     /path/to/dev.crt;
    ssl_certificate_key /path/to/dev.key;
}
```

## 3. Check it with curl

Tell `curl` to trust the certificate for one request:

```bash
curl --cacert dev.crt https://localhost:8443/
curl --cacert dev.crt --resolve myapp.localhost:8443:127.0.0.1 https://myapp.localhost:8443/
```

## 4. Trust it on your machine

To stop browser warnings, add the certificate to the operating system's trust store. Only do this with a certificate whose private key stays on your machine.

```bash
# Debian and Ubuntu
sudo cp dev.crt /usr/local/share/ca-certificates/certtool-dev.crt
sudo update-ca-certificates

# Fedora and RHEL
sudo cp dev.crt /etc/pki/ca-trust/source/anchors/certtool-dev.crt
sudo update-ca-trust

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain dev.crt
```

```powershell
# Windows, for the current user (no administrator needed)
Import-Certificate -FilePath dev.crt -CertStoreLocation Cert:\CurrentUser\Root
```

Firefox keeps its own trust store. Import `dev.crt` under **Settings > Privacy & Security > Certificates > View Certificates > Authorities**.

## 5. Remove it when you are done

```bash
# Debian and Ubuntu
sudo rm /usr/local/share/ca-certificates/certtool-dev.crt
sudo update-ca-certificates --fresh

# macOS
sudo security delete-certificate -c myapp.localhost /Library/Keychains/System.keychain
```

```powershell
# Windows
Get-ChildItem Cert:\CurrentUser\Root | Where-Object Subject -like '*CN=myapp.localhost*' | Remove-Item
```

## Several services

If you trust one self-signed certificate per service, you have to trust each of them separately. Instead, create a local CA once, trust only the CA, and sign every development certificate with it. See [Private CA and mutual TLS](private-ca.md).
