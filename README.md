# Reduction

An opinionated reverse proxy built in Rust for machine-to-machine communication over constrained networks.

Reduction is designed for environments where AI agents and devices communicate with cloud backends over unreliable connections. It prioritizes low overhead, mutual TLS authentication, and efficient binary serialization — with no browser or human-facing concerns.

## Key design decisions

- **QUIC-first networking** — QUIC via `quinn` is the default transport. TCP is available as a fallback. A connection is either all-QUIC or all-TCP, configured per listener — no protocol translation.
- **mTLS only** — Mutual TLS is the sole authentication mechanism. Both client and server present certificates, validated against a shared CA. No token auth, no API keys.
- **Zstd compression** — No gzip, no brotli. Zstd is the only supported compression algorithm.
- **Bitcode serialization** — Control-plane communication between proxy nodes uses [Bitcode](https://crates.io/crates/bitcode) for compact binary encoding.
- **TOML configuration** — All configuration lives in a single TOML file with hot-reload support.
- **No SSH, no browser protocols** — This proxy serves machines, not people.

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

On top of base weights, **IP-seeded jitter** prevents thundering-herd scenarios when many clients arrive simultaneously. A per-backend **request queue with backpressure** buffers requests ahead of dispatch.

Backend health data (received via a pub/sub control plane) factors into weight calculations. If the control plane is unreachable, the proxy falls back to local-only decisions using base weights and queue backpressure.

### Modules

| Module | Purpose |
|---|---|
| `balancer` | Rendezvous hashing, jitter, request queue with backpressure |
| `compression` | Zstd compress/decompress |
| `config` | TOML loading, validation, hot-reload file watcher |
| `health` | Backend health state tracking and subscriber notifications |
| `metrics` | OpenTelemetry integration (OTLP export) |
| `proxy` | Request handler, path-based router, connection pooling |
| `ratelimit` | Token-bucket rate limiting (via `governor`) |
| `tls` | mTLS setup for both server and client sides |
| `transport` | QUIC and TCP listener implementations for axum |

## Getting started

### Prerequisites

- **Rust 2024 edition** (1.85+)
- TLS certificates (CA cert, server cert + key, client cert + key)

### Build

```sh
cargo build --release
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

#### Optional sections

```toml
[balancer]
queue_depth = 1000        # max queued requests per backend (default: 1000)
jitter_factor = 0.05      # weight jitter 0.0–1.0 (default: 0.05)

[ratelimit]
requests_per_second = 10000

[metrics]
otlp_endpoint = "http://localhost:4317"
```

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

## Configuration hot-reload

Reduction watches the config file for changes and rebuilds routes and backend pools without restarting. TLS certificates are not reloaded — a restart is required for cert changes.

## License

MIT
