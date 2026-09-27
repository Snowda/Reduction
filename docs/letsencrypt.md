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
[tls.server.acme]
domains = ["proxy.example.com"]
acme_email = "ops@example.com"
ca_cert_path = "certs/client-ca.crt"   # Private CA for verifying client certs
cache_dir = "./acme_cache"              # Where to store account + certs
staging = false                         # true = Let's Encrypt staging
# Optional: point at a private ACME CA (step-ca, smallstep, a pebble test server) instead of
# Let's Encrypt. When set, it overrides the staging/production URL.
# directory_url = "https://acme.internal/dir"
# directory_ca_cert = "certs/acme-ca.pem"  # Trust root for the ACME server's own HTTPS endpoint

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/client-ca.crt"
```

### Secret-state custody

By default the ACME **secret state** — the account credentials and the certificate private key — is
stored as a single `acme_state.json` blob in `cache_dir` (plaintext on the local filesystem). For a
deployment that must keep secrets off persistent plaintext storage, put that state under **Barrel**
custody instead:

```toml
[tls.server.acme.barrel_state]
# env_var = "REDUCTION_ACME_STATE"   # where the Barrel agent injects the state blob at launch (default)
persist_command = ["barrel-agent", "run", "reduction-acme-store"]   # hash-pinned; runs to persist renewed state
```

With `[barrel_state]` present:

- **Load** — at launch, the Barrel agent injects the opaque state blob into `env_var` (single-line
  JSON). Reduction reads it there; `cache_dir` is never touched.
- **Persist** — when a certificate is provisioned or renewed, Reduction runs `persist_command` with the
  updated blob on its **stdin**. The command (a Barrel-registered, hash-pinned entry) writes it into the
  vault. Barrel's broker never returns a secret over the wire, so this one-way env-in / command-out shape
  is what keeps custody in Barrel without changing Barrel's protocol.
- **Fail-closed** — if the persist command fails, renewal is retried with backoff and the in-memory
  certificate keeps serving; Barrel's last-known-good state is left untouched (no partial write). If the
  state is missing at launch (no injection), Reduction provisions fresh and fails closed if that also
  fails — it never falls back to a plaintext file.

**Operator step (Barrel side):** register the hash-pinned store command that reads the blob from stdin
and writes it to the vault, and grant the Reduction service access only to its own ACME state, e.g.:

```bash
barrel agent register reduction-acme-store /usr/local/bin/reduction-acme-store --secret REDUCTION_ACME_STATE
```

(The exact store program and secret name are your deployment's choice; it must consume the blob on stdin
and exit non-zero on failure so Reduction fails closed.)

### Manual mode (current default, no change needed)

```toml
[tls.server.manual]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"
```

The mode is selected explicitly by the sub-table you write: `[tls.server.acme]` for ACME, or
`[tls.server.manual]` for static certs. Exactly one must be present. A misspelled field is reported by
name (e.g. `unknown field cert_pathh`), and a misspelled mode names the alternatives (`unknown variant
manuel, expected manual or acme`), rather than the old opaque "did not match any variant" from shape
sniffing.

## Requirements

1. **Port 443** must be accessible from the internet. The `tls-alpn-01` challenge requires Let's Encrypt to connect to your server on port 443.

2. **DNS** for each domain in `domains` must resolve to your server's public IP.

3. **Outbound HTTPS** to `acme-v02.api.letsencrypt.org` (or the staging URL) must be allowed.

## How it works

1. On first startup, the proxy contacts Let's Encrypt and creates an ACME account, recording its credentials into the secret-state store (the `acme_state.json` blob in `cache_dir`, or Barrel custody — see above).

2. For each domain, it performs a `tls-alpn-01` challenge:
   - Generates a temporary self-signed certificate with the (RFC 8737-critical) ACME validation extension
   - Presents it to Let's Encrypt's validation server via the `acme-tls/1` ALPN protocol
   - Normal traffic uses `h2` / `http/1.1` ALPN and is unaffected

   The listener inspects each ClientHello and routes it by ALPN: `acme-tls/1` validation connections
   are served the challenge certificate on a **no-client-auth** config and closed without ever
   reaching the HTTP layer, while all real traffic goes through the mandatory-mTLS config. The
   validator (which presents no client certificate) is therefore accepted for validation without
   any relaxation of client mTLS for real requests.

3. After validation, downloads the certificate chain and persists it — with the account credentials and the private key — as one atomic blob through the secret-state store.

4. A background task sleeps until 30 days before certificate expiry, then renews automatically.

5. On subsequent startups, the cached certificate is loaded immediately. Renewal only happens if the cert is within the 30-day renewal window.

## Staging vs production

Always test with `staging = true` first. Let's Encrypt production has strict rate limits:
- 5 duplicate certificates per week
- 50 certificates per registered domain per week

Staging certificates are not publicly trusted but have much higher limits.

## Cache directory (file store)

When no `[barrel_state]` is configured, the `cache_dir` (default: `./acme_cache`) holds the secret
state as a single blob:

```
acme_cache/
  acme_state.json   # ACME account credentials + certificate chain + private key (one atomic blob)
```

This file lets an attacker issue certificates for your domains and holds your server's private key, so
protect it — recommended permissions `chmod 700 acme_cache/` — or move it off persistent plaintext
storage entirely with Barrel custody (see **Secret-state custody** above). Deployments upgrading from
the earlier three-file layout (`account_credentials.json` / `cert.pem` / `key.pem`) simply re-provision
on first start under the new format.

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
