# Reduction

An opinionated reverse proxy built in Rust for machine-to-machine communication over constrained networks.

Reduction is designed for environments where AI agents and devices communicate with cloud backends over unreliable connections. It prioritizes low overhead, mutual TLS authentication, and efficient binary serialization — with no browser or human-facing concerns.

## Features

- **QUIC-first networking** — QUIC via `quinn` is the default transport. TCP is available as a fallback. Transport is configured independently on the listener and backend sides.
- **mTLS only** — Mutual TLS is the sole authentication mechanism. Both client and server present certificates, validated against a shared CA. No token auth, no API keys.
- **Zstd compression** — Zstd is the only supported compression algorithm. Configurable level (1–22), minimum size threshold, and built-in zip-bomb protection.
- **Circuit breaker** — Per-backend failure detection with configurable thresholds. Automatically stops sending traffic to failing backends and probes them during recovery.
- **Retry with backoff** — Exponential backoff with jitter on failed requests. Configurable retry count, delay bounds, and jitter.
- **Access control** — IP-based allow/deny lists with CIDR support.
- **Rate limiting** — Per-IP token-bucket rate limiting via `governor`.
- **Hot-reload** — Config file changes (routes, backends, weights) and TLS certificates are picked up automatically without restarting the proxy.
- **TOML configuration** — All configuration lives in a single TOML file.
- **Graceful shutdown** — In-flight connections drain before the proxy exits, with a configurable timeout.

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
        ▼                           │
  Path-based routing          Config watcher
        │                    (hot reload via fs notify)
        ▼
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
```

### Load balancing

Reduction uses **rendezvous hashing** (highest random weight) to assign clients to backends deterministically. This gives stable client affinity with minimal disruption when backends are added or removed.

On top of base weights, **IP-seeded jitter** prevents thundering-herd scenarios when many clients arrive simultaneously. A per-backend **request queue with backpressure** buffers requests ahead of dispatch and factors into backend selection so overloaded backends receive less traffic.

Backend health data (received via a pub/sub control plane) factors into weight calculations. If the control plane is unreachable, the proxy falls back to local-only decisions using base weights and queue backpressure.

### Observability

Reduction exposes metrics via OpenTelemetry and supports OTLP trace export with configurable sampling.

| Metric | Type | Description |
|---|---|---|
| `proxy.requests.total` | Counter | Total proxied requests |
| `proxy.request.duration_ms` | Histogram | End-to-end request latency |
| `proxy.connections.active` | Gauge | Currently open connections |
| `proxy.queue.depth` | Gauge | Requests waiting in backend queues |
| `proxy.rate_limit.rejections` | Counter | Requests rejected by rate limiter |
| `proxy.backend.selections` | Counter | Backend selection events |
| `proxy.backend.active_connections` | Gauge | Active connections per backend |
| `proxy.backend.conn_limit_rejected` | Counter | Requests rejected due to connection limits |
| `proxy.circuit.open_total` | Counter | Circuit breaker open transitions |
| `proxy.circuit.half_open_probes` | Counter | Half-open probe attempts |
| `proxy.retry.attempts` | Counter | Retry attempts |

### Modules

| Module | Purpose |
|---|---|
| `balancer` | Rendezvous hashing, jitter, request queue with backpressure |
| `circuit` | Per-backend circuit breaker (closed → open → half-open → closed) |
| `compression` | Zstd compress/decompress with zip-bomb protection |
| `config` | TOML loading, validation, hot-reload file watcher |
| `health` | Backend health state tracking and subscriber notifications |
| `metrics` | OpenTelemetry counters, gauges, and histograms (OTLP export) |
| `proxy` | Request handler, path-based router, connection pooling |
| `ratelimit` | Token-bucket rate limiting (via `governor`) |
| `tls` | mTLS setup and certificate hot-reload |
| `transport` | QUIC and TCP listener implementations |
| `acl` | IP allow/deny access control with CIDR matching |

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

## Configuration reference

See [docs/configuration.md](docs/configuration.md) for the full reference of every config section, field, and default.

## License

MIT
