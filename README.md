# Reduction

An opinionated reverse proxy built in Rust for machine-to-machine communication over constrained networks. Designed for AI agents and devices talking to cloud backends over unreliable connections — low overhead, mutual TLS, efficient binary serialization, no browser concerns.

## Why Reduction?

Most reverse proxies are built for the browser era: HTTP semantics, cookie handling, WebSocket upgrades, enormous configuration surfaces. Reduction strips all of that away and focuses on what M2M traffic actually needs:

- **Single binary, single TOML file.** No YAML sprawl, no control plane, no sidecar.
- **QUIC-native.** QUIC by default, TCP as fallback.
- **NAT traversal built in.** Backends behind NATs register via reverse QUIC tunnels — no VPNs, no port forwarding.
- **Zero-alloc hot paths.** Stack-allocated IDs, no heap churn on the request path.
- **Rust-to-Rust.** If your services are in Rust, Reduction speaks your language end to end.

### Non-goals

Reduction intentionally does not support: WebSocket, gRPC transcoding, HTTP/3 browser negotiation, cookie-based sessions, HTML error pages, JWT or OAuth validation, or plugin/scripting interfaces. If you need these, use a general-purpose proxy.

## Features

### Transport and security

- **QUIC-first networking** — QUIC by default, TCP with HTTP/1.1 and HTTP/2 as fallback. Listener and backend transports configured independently.
- **mTLS only** — Both sides present certificates validated against a shared CA. No token auth, no API keys.
- **Let's Encrypt / ACME** — Optional automatic server certificate provisioning via `tls-alpn-01`. Client mTLS still enforced. Enabled with `--features acme`.
- **TLS certificate hot-reload** — Certificates reload automatically via file watcher, no restart needed.
- **Connection pooling** — Per-backend HTTP/2 and QUIC connection reuse, pre-warmed on startup and after config reload.

### NAT traversal

- **Reverse QUIC tunnels** — Backends behind NATs establish outbound QUIC connections to the proxy and register themselves. Inbound requests route through these tunnels transparently.
- **Session management** — Max sessions per backend, heartbeat keepalive, and allowed-backend whitelist.
- **Stream multiplexing** — Each request opens a new bidirectional stream within an established tunnel. No head-of-line blocking.
- **Raw stream relay** — Non-HTTP QUIC streams relayed bidirectionally for custom binary protocols.

### Reliability

- **Circuit breaker** — Per-backend state machine (closed → open → half-open → closed) with configurable failure threshold, recovery timeout, and probe limit.
- **Retry with backoff** — Exponential backoff with jitter. Configurable retry count and delay bounds.
- **Backpressure** — Per-backend bounded request queue that factors into backend selection so overloaded backends receive less traffic.
- **Connection limits** — Per-backend connection cap with rejection metrics.

### Traffic management

- **Response caching** — LRU cache with Cache-Control parsing (`no-store`, `private`, `max-age`) and method-aware keys.
- **Zstd compression** — Configurable level (1–22), minimum size threshold, and bounded decompression.
- **Access control** — IP allow/deny lists with CIDR support.
- **Rate limiting** — Per-IP token-bucket rate limiting.
- **Path-based routing** — Longest-prefix-first matching with per-route timeout overrides.

### Operations

- **Hot-reload** — Config and TLS certificates picked up automatically. Backend pools rebuild atomically; removed backends drain in-flight connections.
- **Graceful shutdown** — Drains in-flight connections and tunnel sessions, force-closes after a configurable timeout.
- **TOML configuration** — Single file with validation on load and sensible defaults.
- **Granular timeouts** — Independent connect, handshake, request, idle relay, and drain timeouts, with per-route overrides.

## Architecture

```
Clients (Rust services / AI agents)
        │
        ▼
  ┌───────────┐      mTLS + QUIC/TCP
  │ Reduction │◄────────────────────┐
  │   Proxy   │                     │
  └─────┬─────┘                     │
        │                           │
   ┌────┴────┐                Config watcher
   │         │             (hot reload via fs notify)
   ▼         ▼
 Path      Tunnel            Backends behind NATs
 router    registry  ◄─────  register via reverse
   │         │                QUIC tunnels
   ▼         ▼
  ┌─────────────────┐
  │  Backend Pool   │
  │  (rendezvous    │
  │   hashing +     │
  │   jitter)       │
  └────────┬────────┘
           │
     ┌─────┼─────┐
     ▼     ▼     ▼
   [ Backend servers ]
     (direct or tunneled)
```

### Load balancing

**Rendezvous hashing** assigns clients to backends deterministically with stable affinity and minimal disruption when backends change. **IP-seeded jitter** prevents thundering-herd scenarios, and per-backend **backpressure** steers traffic away from overloaded backends.

Backend health data factors into weight calculations with configurable latency thresholds and staleness TTL. If the control plane is unreachable, the proxy falls back to local-only decisions.

### Observability

OpenTelemetry metrics (OTLP export) cover requests, latency, connections, queue depth, rate limiting, circuit breaker transitions, cache hits, tunnel sessions, and raw relay activity. W3C Trace Context (`traceparent`) is propagated across hops with configurable sampling. See [docs/configuration.md](docs/configuration.md) for the full metrics reference.

## Getting started

### Prerequisites

- **Rust 2024 edition** (1.85+)
- TLS certificates (CA cert, server cert + key, client cert + key)

### Build

```sh
cargo build --release
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

[tls.server]
cert_path = "certs/server.crt"
key_path = "certs/server.key"
ca_cert_path = "certs/ca.crt"

[tls.client]
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
listen_address = "0.0.0.0:8444"
allowed_backend_ids = ["edge-agent-1", "edge-agent-2"]
```

All other sections are optional and use sensible defaults. See `config.example.toml` for the full reference.

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

### Test

```sh
cargo test
```

## Examples

| Example | What it demonstrates |
|---|---|
| [`demo.rs`](examples/demo.rs) | mTLS setup, JSON echo backend, request forwarding, health updates, config reload |
| [`mcp_demo.rs`](examples/mcp_demo.rs) | MCP servers as backends, rendezvous hashing determinism, health-aware failover |
| [`acl_demo.rs`](examples/acl_demo.rs) | All four ACL modes: allow-only, deny-only, combined, disabled |
| [`tunnel_demo.rs`](examples/tunnel_demo.rs) | NAT traversal with a simulated backend registering via reverse QUIC tunnel |
| [`profile_loadtest.rs`](examples/profile_loadtest.rs) | Concurrent load driver with latency percentile reporting and optional Perfetto trace output |

Run any example with:

```sh
cargo run --example demo
```

## Benchmarks

Criterion benchmarks cover the hot-path components:

```sh
cargo bench
```

| Benchmark | Target |
|---|---|
| `router_bench` | Path-prefix matching throughput |
| `balancer_bench` | Rendezvous hashing + jitter selection |
| `compression_bench` | Zstd compress/decompress at various levels |
| `ratelimit_bench` | Per-IP token-bucket throughput |
| `health_bench` | Health weight factor calculations |
| `tls_cache_bench` | Certificate resolver cache performance |

## Configuration reference

See [docs/configuration.md](docs/configuration.md) for the full reference of every config section, field, and default.

## License

MIT
