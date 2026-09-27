# Configuration Reference

Reduction is configured via a single TOML file. All sections below are optional unless noted. Defaults are shown in parentheses.

See `config.example.toml` in the project root for a complete annotated example.

## `[listen]` (required)

| Field | Description |
|---|---|
| `address` | Socket address to bind (e.g. `"0.0.0.0:8443"`) |
| `transport` | `"quic"` or `"tcp"` |
| `client_auth` | (optional, default `"required"`) inbound client-certificate policy — see below |

### `client_auth` — inbound client-certificate policy

Governs whether the public listener requires an mTLS client certificate. It is **never inferred from
the TLS mode** — an ACME-provisioned server can still be mandatory-mTLS, and a manual-cert server can
still be public.

| Value | Behavior |
|---|---|
| `"required"` (default) | Mandatory mTLS. A client presenting no certificate is rejected at the TLS handshake **and** at the application admission gate. This is the historical, secure default — existing configs are unchanged. |
| `"optional"` | A client certificate is requested and, if presented, verified against the `[tls.server]` CA; a client presenting none is still admitted (anonymous). |
| `"disabled"` | Public-browser mode. No client certificate is requested and none is required, so an anonymous browser completes the handshake. The `[tls.server]` `ca_cert_path` is then unused for inbound verification (it must still be present as a field). |

Under `optional`/`disabled`, an anonymous request is forwarded with **no** `x-reduction-client-id` /
`x-reduction-client-spki` identity headers (any client-supplied values are still stripped). A presented
certificate that is **revoked** is still rejected under every policy — disabling mandatory auth relaxes
the nameless-peer gate only, not revocation of an authenticated peer.

## `[http_redirect]` (optional)

A minimal cleartext listener (typically port 80) that answers **every** request with a permanent redirect
to the canonical HTTPS origin. It never proxies content — it exists only so a browser typing `http://`
lands on `https://`. Disabled by default.

| Field | Required | Default | Description |
|---|---|---|---|
| `enabled` | no | `false` | Turn the redirect listener on |
| `listen` | no | `"0.0.0.0:80"` | Cleartext bind address (needs its own port, not `[listen]`'s) |
| `to_host` | when enabled | — | Canonical HTTPS host (bare `host` or `host:port`) to redirect to |

The redirect is a **308 Permanent Redirect** to `https://{to_host}{path}{?query}` — the request's path and
query are preserved, its body is ignored, and its `Host` header is **not** used (the configured `to_host`
is always used, so the redirect cannot be pointed at an attacker-supplied host). Config load rejects an
enabled redirect with an empty/URL-shaped `to_host`, or a `listen` that collides with `[listen].address`.

## `[health_endpoint]` (optional)

A small cleartext HTTP endpoint, separate from the public data plane, for an orchestrator or load
balancer to probe. Disabled by default; bind it to a **private** address (loopback or a management
interface) — it serves no proxy traffic.

| Field | Required | Default | Description |
|---|---|---|---|
| `enabled` | no | `false` | Turn the health endpoint on |
| `listen` | no | `"127.0.0.1:9090"` | Bind address (needs its own port, distinct from `[listen]` and `[http_redirect]`) |

Routes:

- `GET /livez` — always `200 alive` while the process is up (so "process dead" — connection refused — is distinguishable from "not ready").
- `GET /readyz` — `200 ready` once startup is complete (under ACME, the initial certificate is provisioned); `503` while starting, and `503 draining` once graceful shutdown begins, so a load balancer withdraws traffic during the drain window.

## `[tls.server.manual]` (server identity) / `[tls.client]` (backend identity)

The server TLS mode is chosen by an explicit sub-table: `[tls.server.manual]` for static certificate
files (below), or `[tls.server.acme]` for Let's Encrypt / ACME provisioning (see `docs/letsencrypt.md`).
The server always needs its own identity (a `[tls.server.*]` table is mandatory). `[tls.server.manual]`
and `[tls.client]` share the same fields. The server identity is presented to incoming clients; the
client identity is used when connecting to backends.

**`[tls.client]` is optional.** It is required only when at least one backend performs a TLS handshake
upstream — any backend with `transport = "quic"` (QUIC always uses mTLS) or `scheme = "https"`. A pure
plaintext-backend deployment (every backend `transport = "tcp"` + `scheme = "http"`, e.g. a public blog
in front of a cleartext static-site server) dials no TLS upstream and may omit `[tls.client]` entirely.
Startup **rejects** a config that omits it while a backend still needs it, naming the offending backend;
a present-but-unused `[tls.client]` is allowed but **warns** (drop it to keep a public host free of unused
mTLS material).

| Field | Description |
|---|---|
| `cert_path` | Path to the PEM certificate |
| `key_path` | Path to the PEM private key |
| `ca_cert_path` | Path to the CA certificate(s) for peer validation — a multi-PEM bundle is allowed |
| `crl_path` | (server only, optional) Path to a CA-signed CRL enforced at the handshake |

Certificates are hot-reloaded automatically when the files change on disk. Both the server's and the
client's `ca_cert_path` trust bundles are hot-reloaded too — see below.

### `crl_path` — handshake-level revocation (server only)

Setting `crl_path` on `[tls.server.manual]` makes the proxy enforce a **CA-signed X.509 CRL** (PEM,
`-----BEGIN X509 CRL-----`) during the mTLS handshake: a revoked client certificate is rejected before
any tunnel or request is seen, on both the TCP and QUIC listeners. The file is hot-watched — dropping a
new CRL in replaces the old one live, with no restart. A stale CRL (past its `nextUpdate`) is rejected,
and a corrupt/unreadable CRL keeps the previous one in force (last-known-good) rather than disabling
verification. `crl_path` on `[tls.client]` is ignored.

This complements, and is distinct from, the application-level `tunnel.revocation_path` denylist:

- **CRL (`crl_path`)** rejects at the TLS handshake, requires a **CA-signed** artifact (the CA must
  sign CRLs), and covers *any* mTLS peer (tunnel registration and proxied requests alike).
- **Denylist (`tunnel.revocation_path`)** rejects at the application layer, is a plain operator/fleet
  TOML (no CA signature), keys by SPKI or `backend_id`, and additionally sweeps *live* tunnel sessions.

Use the denylist for fleet-driven flag→revoke automation; add `crl_path` when you also want revoked
certs turned away at the handshake itself. Neither requires the other.

### `ca_cert_path` — trust-anchor (CA bundle) hot-reload (both sides)

Both trust stores are **hot-watched**: drop a new CA bundle in and it replaces the old one live, with no
restart and without dropping live QUIC tunnel sessions. This makes CA rotation a routine operation —
root rollover, cross-sign windows, or adding a per-environment intermediate — rather than a restart that
resets every NAT'd fleet device.

- **Server side — `[tls.server.manual] ca_cert_path`** (or `[tls.server.acme] ca_cert_path`) verifies inbound **client** certs (mTLS peers on the TCP
  and QUIC listeners).
- **Client side — `[tls.client] ca_cert_path`** verifies the **backend/upstream server** certs Reduction
  dials. It hot-reloads the same way: the verifier's roots swap in place and the shared client TLS config
  is reused by the connection pool, so a backend-CA rotation takes effect on the next backend handshake
  with no restart. This applies only when `[tls.client]` is present (a backend needs TLS); a
  plaintext-backend deployment loads no client identity and has no client-side trust to reload.

Both sides share the same semantics:

- **Multi-root bundle / cross-sign window.** `ca_cert_path` may hold several PEM certificates. Trust
  both the old and new roots at once by placing both in the file; once migration completes, remove the
  old root and the reload stops trusting it.
- **Last-known-good.** An unparseable **or empty** bundle keeps the previous trust anchors in force,
  logs an error, and increments `proxy.ca_bundle.load_errors` (with a `side` attribute — `server` or
  `client`). An empty trust store would reject the whole fleet (server side) or make every backend
  unreachable (client side), so the reload fails toward availability, loudly — it never empties the
  store. A successful reload increments `proxy.ca_bundle.reloads` (same `side` attribute); pair the two
  to alert on staleness (errors climbing while reloads stay flat). At **startup** an empty/missing/garbage
  bundle fails fast instead — booting with no trust is never correct.
- **CRL carried through (server side).** A server-side trust reload rebuilds the verifier with the
  *current* CRL (when `crl_path` is set), so revocation keeps applying across a CA rotation. `crl_path`
  does not apply to the client side.
- **ACME.** Under `[tls.server.acme]`, only Reduction's own server certificate is ACME-provisioned;
  inbound client-cert verification still trusts `ca_cert_path` and hot-reloads exactly as on the manual
  path (no handshake CRL, since ACME config carries none). Under ACME, **`ca_cert_path` is optional**: it
  is the inbound client-cert CA, required only when `listen.client_auth` is `"required"` or `"optional"`
  (the policies that build an inbound verifier) — startup rejects an ACME config that omits it under those
  policies. Under `client_auth = "disabled"` (public-browser mode) no verifier is built and the CA is
  never read, so it should be omitted (a present one is simply unused). The client-side (`[tls.client]`)
  reload is active whenever a client identity is loaded, regardless of the server's TLS mode.

## Client identity headers

Because mTLS is mandatory on the proxy listener, every accepted connection has a certificate-proven
identity. Reduction propagates that identity to the backend on every forwarded request via two headers:

| Header | Value |
|---|---|
| `x-reduction-client-id` | The leaf certificate's subject Common Name (CN), verbatim — the canonical client/device ID |
| `x-reduction-client-spki` | Lowercase hex of the SHA-256 over the leaf certificate's SubjectPublicKeyInfo (DER), disambiguating CN collisions |
| `x-forwarded-for` | The connection's real client IP (single value — Reduction is the mTLS edge, not a proxy chain) |
| `x-real-ip` | Same client IP, for backends that read this alias |

Rules a backend must rely on:

- **These headers are stripped from the incoming request and re-injected from the verified handshake
  identity / connection.** A client that sends its own `x-reduction-client-id`/`x-reduction-client-spki`,
  or its own `x-forwarded-for`/`x-real-ip`, cannot spoof another device or IP — the client-supplied
  value is removed before injection and never reaches the backend. Each header carries exactly one value.
- **`x-forwarded-proto`, `x-forwarded-host`, and `forwarded` are stripped without replacement** —
  Reduction does not vouch for them, so a backend must not read them.
- **Trust these headers only when the network path from Reduction to the backend is private.** They are
  plaintext HTTP; anything that can reach the backend directly (bypassing Reduction) can forge them.
  Bind backends to a loopback/private interface or a mutually-authenticated link.
- **Cache keying.** The response cache keys on method + path **+ client identity** (the connection's
  mTLS SPKI fingerprint), so a response cached for one device is never served to another; anonymous
  (non-mTLS) connections share an empty-identity key. The cache also refuses to store a response that
  `Vary`s on a request dimension it does not key on (any header other than `Accept-Encoding` — which
  Reduction normalizes itself — or the injected `x-reduction-client-*` headers; `Vary: *` is never
  cached), and it will not store a response to an `Authorization`-bearing request unless the backend
  marked it `Cache-Control: public`. Backends can still opt out entirely with `private` or `no-store`.
  Note that identity keying means public assets are cached per-device; front an identity-independent
  backend without client certs if you want cross-device sharing.

## `[timeouts]`

| Field | Default | Description |
|---|---|---|
| `connect_secs` | 5 | TCP/QUIC connection timeout |
| `handshake_secs` | 5 | TLS handshake timeout |
| `request_secs` | 30 | Time-to-response-headers timeout (overridable per route via `timeout_secs`) |
| `response_idle_secs` | 60 | Max gap between response-body frames; a backend that stalls longer has its stream aborted, releasing the connection permit, queue slot, and active-connection gauge it held |

## `[balancer]`

| Field | Default | Description |
|---|---|---|
| `queue_depth` | 1000 | Max queued requests per backend |
| `drain_timeout_secs` | 30 | Time to drain connections when removing a backend |
| `max_backends` | 64 | Max backends per pool (hard limit: 256) |

## `[circuit_breaker]`

| Field | Default | Description |
|---|---|---|
| `failure_threshold` | 5 | Consecutive failures before opening the circuit |
| `recovery_timeout_secs` | 60 | How long a circuit stays open before probing |
| `half_open_max_requests` | 2 | Probe requests allowed in half-open state |

## `[retry]`

| Field | Default | Description |
|---|---|---|
| `max_retries` | 2 | Max retry attempts after initial failure |
| `base_delay_ms` | 200 | Initial backoff delay |
| `max_delay_ms` | 2000 | Backoff cap |
| `jitter_ms` | 100 | Random jitter added to each delay |

## `[ratelimit]`

| Field | Default | Description |
|---|---|---|
| `requests_per_second` | unlimited | Per-IP request rate |

## `[access]`

| Field | Default | Description |
|---|---|---|
| `allow` | `[]` | IP/CIDR allowlist (if non-empty, only these IPs are permitted) |
| `deny` | `[]` | IP/CIDR denylist |

## `[compression]`

| Field | Default | Description |
|---|---|---|
| `enabled` | `true` | Apply the zstd response transform when the client accepts it. Set `false` to pass backend bodies through untransformed (e.g. a public browser cutover). A body the backend already encoded is never re-encoded regardless. |
| `level` | 3 | Zstd compression level (1–22) |
| `min_bytes` | 256 | Skip compression below this body size |

## `[proxy]`

| Field | Default | Description |
|---|---|---|
| `max_response_body_bytes` | 10 MB | Maximum response body size |
| `max_request_body_bytes` | 10 MB | Cap on request bodies held in memory (retry buffering and zstd request decompression). Bodies declaring a larger Content-Length stream through in a single attempt (no retries); chunked bodies exceeding the cap are rejected with 413 |
| `h2_connections_per_backend` | 4 | HTTP/2 connections per backend |
| `max_idle_quic_per_host` | 16 | Idle QUIC connections per host |
| `h2_stream_window` | 2 MB | HTTP/2 per-stream flow control window |
| `h2_conn_window` | 4 MB | HTTP/2 per-connection flow control window |
| `inline_compress_threshold` | 8192 | Bodies at or below this size compress inline; larger ones use a blocking task |
| `quic_channel_capacity` | 256 | Bounded channel size for QUIC stream accept queue |

## `[metrics]`

Metrics are always collected in-process; this section only controls **export**. With no `[metrics]`
section (or `otlp_endpoint` unset) the OpenTelemetry instruments still record, but nothing is pushed
off-box.

| Field | Default | Description |
|---|---|---|
| `otlp_endpoint` | none | OTLP HTTP endpoint for metric export (e.g. `"http://localhost:4318"`). When set, a periodic reader pushes metrics there; when unset, metrics are recorded but not exported |

This is distinct from `[tracing].otlp_endpoint`, which exports *traces*. The two are configured
independently and may point at the same collector or at different ones.

## `[tracing]`

| Field | Default | Description |
|---|---|---|
| `otlp_endpoint` | none | OTLP HTTP endpoint for trace export |
| `sample_ratio` | 1.0 | Trace sampling ratio (0.0–1.0) |

## `[cache]`

An optional in-process LRU response cache for `GET`/`HEAD` responses. Disabled unless `enabled = true`.

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Opt in to response caching (no caching by default) |
| `max_entries` | 1000 | LRU capacity (entry count) |
| `max_entry_bytes` | 1 MB | Reject caching any single response body larger than this |
| `default_ttl_secs` | 60 | Fallback TTL when a response carries no `Cache-Control: max-age` |

**The cache key includes client identity.** Entries are keyed on method + path **+ the connection's
mTLS SPKI fingerprint**, so a response cached for one device is never served to another; anonymous
(non-mTLS) connections share an empty-identity key. This means public assets are cached per-device —
front an identity-independent backend without client certs if you want cross-device sharing. See
[Client identity headers → Cache keying](#client-identity-headers) for the full keying, `Vary`, and
`Authorization` rules. `Cache-Control: no-store`/`private` skip caching; `max-age` sets the TTL.

## `[health]`

| Field | Default | Description |
|---|---|---|
| `staleness_ttl_secs` | 300 | Health data older than this is ignored |

## `[[backends]]`

| Field | Required | Default | Description |
|---|---|---|---|
| `id` | yes | — | Unique backend identifier |
| `address` | yes | — | Backend socket address |
| `weight` | yes | — | Load balancing weight (≥ 0) |
| `transport` | yes | — | `"quic"` or `"tcp"` |
| `scheme` | no | `"https"` | Backend hop security — see below |
| `host` | no | IP from address | The `Host` header sent to the backend (and, for `https`, the TLS SNI / cert-validation name). Set this to the site's canonical host (e.g. `conorforde.com`) to have the backend see that Host; the client's own Host header is not forwarded. |
| `pool` | no | same as `id` | Pool grouping key |
| `max_connections` | no | 256 | Max concurrent connections to this backend |

### `scheme` — backend hop security

Orthogonal to `transport` (the wire protocol). Chooses whether the hop to the backend is encrypted:

| Value | Behavior |
|---|---|
| `"https"` (default) | TLS to the backend, with HTTP/2, verified against the `[tls.client]` CA. The historical, secure default — existing configs are unchanged. |
| `"http"` | Cleartext HTTP/1.1, no TLS. For a plain-HTTP backend on a trusted private network (e.g. a static-site server on an isolated Compose network). |

Only valid with `transport = "tcp"` — QUIC always uses TLS, so `scheme = "http"` on a QUIC backend is
rejected at config load. Cleartext (`http`) connections are dialed fresh per request (not pooled); the
TLS (`https`) path pools HTTP/2 connections per backend as before.

## `[[routes]]`

| Field | Required | Default | Description |
|---|---|---|---|
| `path_prefix` | yes | — | URL path prefix (longest match wins) |
| `backend_id` | yes | — | Target backend `id` |
| `timeout_secs` | no | global `request_secs` | Per-route request timeout override |

## `[tunnel]`

Reverse tunnels let a NAT'd backend dial the proxy over QUIC+mTLS and register a `backend_id`, so
the proxy can route to it without an inbound port. Acceptance has three gates: CA membership (mTLS),
certificate-CN binding (the registered `backend_id` must equal the client cert's CN), and the
revocation denylist below.

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable the reverse-tunnel listener |
| `listen_address` | none | QUIC listen address for backend registration |
| `heartbeat_timeout_secs` | 45 | Drop a session after this long without a heartbeat |
| `max_sessions_per_backend` | 8 | Hard cap on concurrent sessions for one `backend_id` |
| `max_total_sessions` | none | Global cap on concurrent sessions across all backends (accept backpressure); unset = unlimited |
| `max_accepts_per_second_per_ip` | none | Per-source-IP accept rate limit for incoming connections; unset = unlimited |
| `registration_timeout_secs` | 10 | Time allowed to send the Register frame after connecting |
| `control_channel_capacity` | 16 | Bounded control-frame queue per session |
| `allowed_backend_ids` | `[]` | Optional kill-switch (see below) |
| `revocation_path` | none | Path to the revocation denylist (`revoked.toml`) |

`max_total_sessions` is a fleet-wide accept-backpressure limit, enforced at registration on top of the
per-backend `max_sessions_per_backend` bound: once the total live session count reaches it, further
registrations are turned away with a `Shutdown("at capacity")` and counted under
`proxy.tunnel.registration_rejected{reason="global_cap"}`. It is a soft cap (checked against the live
total, not globally locked), which is the intended behavior for a safety/backpressure limit.

`max_accepts_per_second_per_ip` is a per-source-IP token-bucket rate limit on *incoming connections*,
enforced at `accept()` **before** the QUIC handshake: a connection flood from one source is dropped
cheaply (no handshake, no crypto, no task spawn) rather than each connection paying a full handshake
and registration. Drops are silent (`quinn::Incoming::ignore()` — nothing is sent back, so a
spoofed-source flood cannot use the proxy to amplify) and counted under
`proxy.tunnel.accepts_rate_limited`. This complements `max_total_sessions` (which bounds standing
session *count*) by bounding the connection *rate* under load. The per-IP map is swept periodically so
it stays bounded by the active source set. Legitimate reconnect storms should stay well under the
configured rate; size it above your fleet's worst-case simultaneous-reconnect rate per source.

### Revocation denylist (`revocation_path`)

Fleet-scale acceptance accepts *any* cert under the CA **minus** a revocation denylist — you enumerate
only the bad, not every good device. The file is written by the fleet layer and hot-watched: changes
take effect without a restart, cutting off both future registrations and any live session.

```toml
# revoked.toml
[[revoked]]
spki = "a1b2…"              # 64 hex chars: SHA-256 of the cert's SubjectPublicKeyInfo
reason = "clone detected 2026-08-20"

[[revoked]]
backend_id = "edge-013"     # blocks the NAME outright, whatever key it holds
reason = "decommissioned"
```

Each entry names `spki`, `backend_id`, or both; `reason` is **required** (an unexplained revocation is
an audit hole). Prefer **SPKI**: it revokes a *compromised key*, not a device name, so the legitimate
device can re-enroll with a fresh key (new SPKI, same `backend_id`) and regain service while the stolen
key stays dead. Use **`backend_id`** only for the "this device is gone for good" case (decommission) —
revoking a name burns the `backend_id` for any key.

Load and reload fail toward availability, loudly:

- **Unset `revocation_path`** or **absent file** → empty denylist (nothing revoked; a fresh deploy).
- **Unparseable file** → the **previous** denylist stays in force (last-known-good) and
  `proxy.revocation.load_errors` increments. A corrupt feed never un-revokes everyone (fail-open) and
  never bricks the fleet (fail-closed).

Enforcement points and their metrics: registration (`proxy.tunnel.registration_rejected{reason="revoked"}`),
live-session sweep (`proxy.tunnel.sessions_revoked`), and the HTTP request path — a revoked device is
served **403** before routing or cache (`proxy.requests.rejected{reason="revoked"}`).

File trust equals filesystem trust, the same as the TLS keys already on that host. A *signed* feed only
matters when the file is fetched over a network, which is out of scope here.

### `allowed_backend_ids` is a kill-switch, not authentication

Before the revocation denylist existed, `allowed_backend_ids` was the only per-device deny mechanism —
an allowlist that enumerated every *good* device, i.e. O(fleet) config. It is **retained but demoted**:
CA membership + CN binding already authenticate a device, and the revocation denylist handles per-device
denial at fleet scale. Treat `allowed_backend_ids` purely as an operational kill-switch (pin acceptance
to a short explicit set during an incident); leave it empty for normal fleet-scale operation.

## `[[raw_relay_authz]]` — per-device authorization for raw QUIC relays

On the QUIC listener a client may open a **raw** stream (a `0x02` stream-type byte) and name a
`backend_id` in its routing header to get an opaque byte pipe to that backend — the transport-agnostic
counterpart to the HTTP forward path. Unlike the HTTP path, a raw relay cannot inject the caller's proven
identity into the stream (there are no headers in an opaque byte pipe), so the backend never learns
*which* device is connected and cannot authorize per device itself. `[[raw_relay_authz]]` closes that gap
by deciding **at the proxy edge** which authenticated devices may open a raw relay to which backend.

```toml
[[raw_relay_authz]]
backend_id = "api-primary"                # the routing-header backend id a raw client names
allowed_cns = ["device-1", "device-2"]    # device certificate CNs permitted to raw-relay here
allowed_spkis = ["a1b2…"]                 # OR device key SPKI sha256 hashes (64 hex chars each)
```

| Field | Required | Description |
|---|---|---|
| `backend_id` | yes | Backend the entry governs (the value a raw client sends in its routing header) |
| `allowed_cns` | no | Device certificate common names admitted to this backend |
| `allowed_spkis` | no | Device key SPKI SHA-256 hashes (64 hex chars, either case) admitted to this backend |

Semantics:

- **Fail closed.** A backend with **no** entry rejects every raw relay request. Add an entry for each
  backend that should accept raw relays; an empty policy set disables the raw-relay feature safely.
- **CN *or* SPKI.** A device is admitted if its certificate CN is in `allowed_cns` **or** its key SPKI is
  in `allowed_spkis`. Prefer **SPKI** — it pins the *key*, so a CN collision cannot grant access and a
  re-enrolled device (new key) is re-authorized explicitly. `allowed_cns` is the human-readable form.
- **Validated at startup.** A duplicate `backend_id`, an entry naming neither list, or a malformed SPKI
  (not 64 hex chars) aborts boot rather than silently denying at request time.

A denied device is refused the byte pipe before any backend connection and counted under
`proxy.raw_relay.rejected{reason="unauthorized"}` — the same clean-rejection path as the ACL, rate-limit,
missing-identity, and revocation gates that already precede it on the raw path. This only decides *who may
reach the backend*; the backend still does not receive the device identity (inherent to an opaque relay).

Unlike `tunnel.revocation_path`, this policy is read **once at startup** (like `[access]`), not
hot-watched; changing it requires a restart.
