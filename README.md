# Reduction

Reduction is the mTLS edge between a fleet of devices and its backend services. A device can be physical hardware or a virtual machine, container or service. Each one gets its certificate when it is created. It dials in over QUIC, often from behind a NAT or over a slow or lossy link. Reduction proves who each device is and decides what it can reach. It then carries the device's HTTP requests, raw byte streams and site UDP/TCP traffic to the right backend.

## Why Reduction?

- **One identity, everywhere.** The device id in a peer's certificate picks its backend, gates what it may reach, is what revocation names, and reaches the backend as a header.
- **Devices dial out.** Reverse QUIC tunnels and raw relays: no inbound port on the device, and a device keeps its backend when its address changes.
- **Fleet-scale admission.** Trust the CA, minus a hot-reloaded revocation list, so the config grows with the revoked devices, not the fleet.
- **QUIC-first.** QUIC listeners and backends, with TCP (HTTP/1.1 and HTTP/2) as the alternative. QUIC session resumption spares a device that dials again from sending its certificate chain.
- **One binary, one TOML file, hot reload.** No sidecar. An external control plane (such as Moist) can write the config, wake cold services and push backend health.
- **Rust-native clients.** A lean library build (`default-features = false`) gives devices the tunnel protocol, QUIC stream and mTLS client config without the proxy's dependency tree.

It also runs as a public HTTPS edge (ACME, browsers, an HTTP-to-HTTPS redirect) and as an allowlist egress gateway for sandboxes.

### Non-goals

Reduction intentionally does not support: WebSocket, gRPC transcoding, HTTP/3 browser negotiation, cookie-based sessions, HTML error pages, JWT or OAuth validation, response caching, compression, or plugin/scripting interfaces. If you need these, use a general-purpose proxy.

Forward proxying is in scope, but in one narrow form: the `[egress]` CONNECT gateway with a hostname allowlist. Reduction does not do TLS interception (MITM), plain-HTTP forwarding, SOCKS or proxy authentication.

## Features

### Transport and security

- **QUIC or TCP listeners** — `[listen]` picks `quic` or `tcp`; each backend picks its own `transport`. TCP listeners serve HTTP/1.1 and HTTP/2.
- **mTLS by default** — `client_auth = "required"` is the default. `"optional"` admits anonymous clients, and `"disabled"` is public-browser mode.
- **Backend hop choice** — `scheme = "https"` (TLS, the default) or `"http"` (cleartext, TCP only); `protocol = "h2"` (default) or `"http1"` with a keep-alive pool.
- **Let's Encrypt / ACME** — Optional server certificate provisioning via `tls-alpn-01` on TCP listeners. Build with `--features acme`. See [docs/letsencrypt.md](docs/letsencrypt.md).
- **Hot-reloaded trust** — Server and client certificates, both CA bundles, and an optional handshake CRL (`crl_path`) reload from disk with no restart. A bad file keeps the last good one in force.
- **Keys from the environment** — `key_env` reads a private key that `barrel run` injects, so the key never sits in a file.
- **Session resumption on QUIC** — Manual-cert QUIC listeners resume TLS sessions with per-reload ticket stores; 0-RTT is refused.

### Identity and authorization

- **Device id** — From the leaf's `uid` attribute, or its CN when it has none. `device_id_source = "uid"` refuses CN-only leaves after the cut-over.
- **Identity headers** — `x-reduction-client-id`, `x-reduction-client-spki`, `x-forwarded-for` and `x-real-ip` are stripped from the client request and set from the verified handshake.
- **Per-backend HTTP caller lists** — `[[http_authz]]` limits a backend to listed device ids or key SPKIs.
- **Revocation denylist** — `tunnel.revocation_path` (hot-watched TOML, by SPKI or `backend_id`) blocks tunnel registration, cuts live sessions and returns 403 on the HTTP path.
- **Injected secret headers** — `inject_header` sets a header from an env var on every request to one backend, so the backend can tell the request came through Reduction.

### NAT traversal

- **Reverse QUIC tunnels** — Backends behind NATs dial the proxy over QUIC+mTLS and register a `backend_id` that must equal their certificate's device id. Inbound requests route through these tunnels.
- **Session limits** — Per-backend and global session caps, heartbeat timeout, and a per-IP accept rate limit applied before the QUIC handshake.
- **Stream multiplexing** — Each request opens a new bidirectional stream within an established tunnel. No head-of-line blocking.
- **Control peers** — A control peer on the tunnel listener receives `Wake` frames for cold pools and, with `control_plane_health = true`, pushes backend health.

### Raw relay and ingress

- **Raw QUIC relay** — A raw stream on the QUIC listener names a backend and gets an opaque byte pipe to it. Fail-closed per-backend authorization (`[[raw_relay_authz]]`), global and per-device caps, and per-pool affinity, rate key and announce (`[[raw_relay_pool]]`).
- **UDP and TCP ingress** — `[[ingress]]` listeners on a site-internal network wrap plaintext traffic in an envelope that keeps the peer address. UDP datagrams are batched; each TCP connection gets its own stream. Both ship over QUIC+mTLS raw streams to `transport = "quic"` backends.

### Egress gateway

- **Allowlist CONNECT proxy** — Deny-by-default egress for sandboxed AI agent and CI containers. `HTTPS_PROXY` clients tunnel only to allowlisted `host:port` pairs, and a name that resolves to an internal address is refused. It runs next to the reverse proxy or alone (no `[listen]`/`[tls]`), and ships as a static musl binary on distroless (`Containerfile.egress`). An optional mTLS QUIC uplink pairs an inner gateway with a remote one. See [docs/egress.md](docs/egress.md).

### Reliability

- **Circuit breaker** — Per-backend state machine (closed → open → half-open → closed) with failure threshold, recovery timeout and probe limit. A write blocked past `stall_limit_ms` opens the circuit at once; `failover` picks `reselect` or `pinned`.
- **Retry with backoff** — Exponential backoff with jitter. Configurable retry count and delay bounds.
- **Backpressure** — Per-backend bounded request queue that factors into backend selection so overloaded backends receive less traffic.
- **Connection limits** — Per-backend connection cap with rejection metrics.
- **Cold services** — A route or listener may name a pool with no backend. It answers `503` + `Retry-After`, or with `wakeable = true` holds the request while a control peer starts the service.

### Traffic management

- **Path-based routing** — Longest-prefix-first matching with per-route timeout overrides.
- **Dedicated listeners** — `[[listeners]]` binds extra addresses that each send every request to one pool, hot-added and removed on reload.
- **Traffic splits** — A route or listener can split traffic across pools by weight (canary rollouts), with `identity`, `ip` or `none` stickiness and optional spill.
- **Per-pool HTTP affinity** — `[[http_pool]]` keys a pool on the device id, the source IP, or a path segment (object affinity).
- **Access control** — IP allow/deny lists with CIDR support.
- **Rate limiting** — Per-source token bucket (one per IPv4 address or IPv6 /64), with `429` + `Retry-After`. Reloadable.
- **HTTP-to-HTTPS redirect** — An optional cleartext `[http_redirect]` listener answers `308` to the canonical HTTPS host.

### Operations

- **Hot-reload** — Config and TLS material picked up automatically. Backend pools rebuild and re-warm; removed backends drain in-flight connections. An invalid reload keeps the previous config.
- **Graceful shutdown** — Drains in-flight connections and tunnel sessions, force-closes after a configurable timeout.
- **Health endpoint** — An optional private `[health_endpoint]` serves `/livez` and `/readyz`. `reduction probe <host:port>` checks `/readyz` for container healthchecks.
- **TOML configuration** — Single file with validation on load and on every reload.
- **Granular timeouts** — Independent connect, handshake, request and response-idle timeouts, with per-route overrides.

## Architecture

```
Devices and services (QUIC/TCP)            Site devices (UDP/TCP)
        │                                           │
        ▼                                           ▼
  ┌──────────────────────┐   mTLS + QUIC/TCP  ┌─────────────┐
  │ Reduction            │◄──────────┐        │ [[ingress]] │
  │ [listen] +           │           │        └─────┬───────┘
  │ [[listeners]]        │     Config watcher       │ envelope + batch
  └─────┬───────────┬────┘  (hot reload, fs notify) │
        │           │                               │
        ▼           ▼                               │
   Path router   Raw relay                          │
   + splits      (raw QUIC streams)                 │
        │           │                               │
        ▼           ▼                               ▼
  ┌──────────────────────────────────────────────────┐
  │  Backend pools (weighted rendezvous hashing,     │
  │  health, circuit breakers, queues)               │
  └────────────────────────┬─────────────────────────┘
                           │
              ┌────────────┴─────────────┐
              ▼                          ▼
     [ Direct backends ]        [ Tunnel registry ] ◄── NAT'd backends
     (QUIC, h2, http1, http)                            dial in over QUIC

  Sandboxes ──CONNECT──► [egress] allowlist ──► internet (or uplink)
```

### Load balancing

**Weighted rendezvous hashing** assigns clients to backends deterministically — stable affinity, minimal disruption when backends change, and selection in proportion to configured backend weights. HTTP clients are keyed by their certificate's device id, so a device keeps its backend across address changes and certificate renewals; anonymous clients are keyed by source IP. Per-backend **backpressure** steers traffic away from overloaded backends.

Backend health reports (load, latency, availability) factor into the weights, with a configurable latency threshold and staleness TTL. A control peer pushes them over the tunnel listener when `[tunnel] control_plane_health = true`. Stale reports are ignored, so without a control plane the proxy decides on local state only.

### Observability

OpenTelemetry metrics (OTLP export) cover requests, latency, connections, queue depth, rate limiting, circuit breaker transitions, tunnel sessions, raw relay accounting, ingress, listeners, CA reloads and splits. W3C Trace Context (`traceparent`) is propagated across hops, with OTLP trace export and configurable sampling. See [docs/configuration.md](docs/configuration.md) for the metric names.

## Getting started

### Prerequisites

- **Rust 1.100** (2024 edition), pinned by `rust-toolchain.toml`.
- **Sibling repositories.** `Cargo.toml` path-depends on `../Solo`, `../Barrel`, `../Vasco`, `../Impediment` and `../CoreUtils`. Check them out beside `Reduction/`.
- TLS certificates (CA cert, server cert + key, and a client cert + key for TLS backends).

### Build

```sh
cargo build --release                         # the proxy
cargo build --release --features acme         # with Let's Encrypt / ACME
cargo build --release --no-default-features   # lean client library only (no binary)
```

### Generate test certificates

To try Reduction locally, generate a self-signed CA and certificates:

```sh
mkdir certs

# Create a CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes \
  -subj "/CN=Reduction Test CA"

# Server certificate
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/server.key -out certs/server.csr -nodes \
  -subj "/CN=localhost"
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/server.crt -days 365

# Client certificate
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/client.key -out certs/client.csr -nodes \
  -subj "/CN=test-client"
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/client.crt -days 365
```

### Configure

Copy the example config and edit it for your environment:

```sh
cp config.example.toml config.toml
```

A minimal configuration:

```toml
[listen]
address = "0.0.0.0:8443"
transport = "quic"        # or "tcp"

[tls.server.manual]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]              # needed only when a backend uses quic or https
cert_path = "certs/client.crt"
key_path = "certs/client.key"
ca_cert_path = "certs/ca.crt"

[[backends]]
id = "api-primary"
address = "10.0.0.1:8080"
weight = 3.0
transport = "quic"

[[routes]]
path_prefix = "/api"
backend_id = "api-primary"
```

To enable reverse tunneling for backends behind NATs:

```toml
[tunnel]
enabled = true
listen_address = "0.0.0.0"
listen_port = 8444
revocation_path = "certs/revoked.toml"   # optional denylist
```

All other sections are optional and use sensible defaults. `config.example.toml` covers every section, and `egress.example.toml` is an egress-only gateway.

### Run

```sh
reduction config.toml
```

Or during development:

```sh
cargo run -- config.toml
```

Set the log level via the `RUST_LOG` environment variable:

```sh
RUST_LOG=debug cargo run -- config.toml
```

Check a running proxy's `[health_endpoint]` (exit 0 only on `200` from `/readyz`):

```sh
reduction probe 127.0.0.1:9090
```

### Test

```sh
cargo test
cargo test --features integration_tests --test retry_tests
cargo test --features integration_tests,acme --test acme_pebble_tests   # needs a container runtime
```

### Containers

- [`Containerfile`](Containerfile) — the proxy with `acme`, plus `barrel-agent`, on a distroless image. See [docs/release.md](docs/release.md).
- [`Containerfile.egress`](Containerfile.egress) — a static musl egress gateway on `distroless/static`.

Both build from the parent directory, so the sibling repositories are in the build context.

## Examples

| Example | What it demonstrates |
|---|---|
| [`demo.rs`](examples/demo.rs) | mTLS setup, JSON echo backend, request forwarding, health updates, config reload |
| [`mcp_demo.rs`](examples/mcp_demo.rs) | MCP servers as backends, rendezvous hashing determinism, health-aware failover |
| [`acl_demo.rs`](examples/acl_demo.rs) | All four ACL modes: allow-only, deny-only, combined, disabled |
| [`tunnel_demo.rs`](examples/tunnel_demo.rs) | NAT traversal with a simulated backend registering via reverse QUIC tunnel |
| [`letsencrypt_demo.rs`](examples/letsencrypt_demo.rs) | ACME server certificate with local-CA client mTLS (needs `--features acme`, port 443, public DNS) |
| [`profile_loadtest.rs`](examples/profile_loadtest.rs) | Concurrent load driver with latency percentile reporting and optional Perfetto trace output |

Run any example with:

```sh
cargo run --example demo
```

See [examples/README.md](examples/README.md) for expected output and profiling.

## Benchmarks

Criterion benchmarks cover the hot-path components:

```sh
cargo bench
```

| Benchmark | Target |
|---|---|
| `router_bench` | Path-prefix matching throughput |
| `balancer_bench` | Weighted rendezvous hashing selection |
| `ratelimit_bench` | Per-source token-bucket throughput |
| `health_bench` | Health state updates and bitcode round trips |
| `health_snapshot_bench` | Per-datagram health read: `watch` borrow vs a leased snapshot |
| `ingress_bench` | Ingress batching and envelope encode/decode |
| `shared_map_bench` | Per-backend map and admission-gate variants |
| `tunnel_registry_bench` | Tunnel registry session lookup |

[`comparison/`](comparison/README.md) is a separate package that benchmarks Reduction against NGINX and frp.

## Fuzzing

The [`fuzz/`](fuzz) workspace member holds libFuzzer targets for the untrusted boundaries: request handling, the raw HTTP/1.1 parsers, upstream sends, the ingress envelope, egress `CONNECT`, the redirect and the health route. `cargo test` replays their seeds.

## Documentation

- [docs/configuration.md](docs/configuration.md) — every config section, field, default and metric
- [docs/egress.md](docs/egress.md) — the egress gateway and its uplink
- [docs/letsencrypt.md](docs/letsencrypt.md) — ACME provisioning
- [docs/release.md](docs/release.md) — building and signing a release image

## License

MIT
