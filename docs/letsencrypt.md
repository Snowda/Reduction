# Let's Encrypt / ACME Support

Reduction supports automatic TLS certificate provisioning via Let's Encrypt using the `tls-alpn-01` challenge. This is opt-in and requires the `acme` feature flag.

## When to use ACME vs manual certs

| Scenario | Recommendation |
|----------|---------------|
| All clients are internal services you control | Manual certs with private CA (default) |
| Some clients are external and need publicly-trusted TLS | ACME for server cert |
| Air-gapped or firewalled networks | Manual certs only |
| Rapid prototyping / dev environments | ACME with staging mode |

ACME only provisions the **server** certificate. Client authentication (mTLS) always uses your private CA regardless of mode.

## Building with ACME support

```sh
cargo build --features acme
```

Without the `acme` feature, the binary is smaller and has no ACME-related dependencies.

## Configuration

### ACME mode (Let's Encrypt server cert)

```toml
[tls.server]
domains = ["proxy.example.com"]
acme_email = "ops@example.com"
ca_cert_path = "certs/client-ca.crt"   # Private CA for verifying client certs
cache_dir = "./acme_cache"              # Where to store account + certs
staging = false                         # true = Let's Encrypt staging

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/client-ca.crt"
```

### Manual mode (current default, no change needed)

```toml
[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"
```

The config format is detected automatically: if `domains` and `acme_email` are present, ACME mode activates. If `cert_path` and `key_path` are present, manual mode is used.

## Requirements

1. **Port 443** must be accessible from the internet. The `tls-alpn-01` challenge requires Let's Encrypt to connect to your server on port 443.

2. **DNS** for each domain in `domains` must resolve to your server's public IP.

3. **Outbound HTTPS** to `acme-v02.api.letsencrypt.org` (or the staging URL) must be allowed.

## How it works

1. On first startup, the proxy contacts Let's Encrypt and creates an ACME account (stored in `cache_dir/account_credentials.json`).

2. For each domain, it performs a `tls-alpn-01` challenge:
   - Generates a temporary self-signed certificate with the ACME validation extension
   - Presents it to Let's Encrypt's validation server via the `acme-tls/1` ALPN protocol
   - Normal traffic uses `h2` / `http/1.1` ALPN and is unaffected

3. After validation, downloads the certificate chain and caches it to `cache_dir/cert.pem` and `cache_dir/key.pem`.

4. A background task sleeps until 30 days before certificate expiry, then renews automatically.

5. On subsequent startups, the cached certificate is loaded immediately. Renewal only happens if the cert is within the 30-day renewal window.

## Staging vs production

Always test with `staging = true` first. Let's Encrypt production has strict rate limits:
- 5 duplicate certificates per week
- 50 certificates per registered domain per week

Staging certificates are not publicly trusted but have much higher limits.

## Cache directory

The `cache_dir` (default: `./acme_cache`) contains:

```
acme_cache/
  account_credentials.json   # ACME account (reused across renewals)
  cert.pem                   # Current certificate chain
  key.pem                    # Private key for the certificate
```

Protect this directory:
- `account_credentials.json` allows issuing certs for your domains
- `key.pem` is your server's private key

Recommended permissions: `chmod 700 acme_cache/`

## mTLS is preserved

Even with ACME server certificates, client verification is still enforced. Clients must present a certificate signed by the CA specified in `ca_cert_path`. This means:

- The server has a publicly-trusted certificate (from Let's Encrypt)
- Clients still need certificates from your private CA
- Unauthorized clients are rejected at the TLS handshake

## Limitations

- **Single instance only**: The `tls-alpn-01` challenge requires the server responding to be the one requesting the certificate. If running multiple instances behind a load balancer, only one can complete the challenge. For multi-instance deployments, use manual certs with an external ACME client or DNS-01 challenge.

- **Port 443 required**: Cannot use a non-standard port for the challenge.

- **No wildcard certificates**: `tls-alpn-01` does not support wildcard domains. List each domain explicitly.

## Example

See `examples/letsencrypt_demo.rs` for a complete working example:

```sh
cargo run --features acme --example letsencrypt_demo
```
