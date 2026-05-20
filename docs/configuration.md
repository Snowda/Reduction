# Configuration Reference

Reduction is configured via a single TOML file. All sections below are optional unless noted. Defaults are shown in parentheses.

See `config.example.toml` in the project root for a complete annotated example.

## `[listen]` (required)

| Field | Description |
|---|---|
| `address` | Socket address to bind (e.g. `"0.0.0.0:8443"`) |
| `transport` | `"quic"` or `"tcp"` |

## `[tls.server]` / `[tls.client]` (required)

Both sections share the same fields. The server identity is presented to incoming clients; the client identity is used when connecting to backends. Both are validated against the CA certificate.

| Field | Description |
|---|---|
| `cert_path` | Path to the PEM certificate |
| `key_path` | Path to the PEM private key |
| `ca_cert_path` | Path to the CA certificate for peer validation |

Certificates are hot-reloaded automatically when the files change on disk.

## `[timeouts]`

| Field | Default | Description |
|---|---|---|
| `connect_secs` | 5 | TCP/QUIC connection timeout |
| `handshake_secs` | 5 | TLS handshake timeout |
| `request_secs` | 30 | Per-request timeout (overridable per route via `timeout_secs`) |

## `[balancer]`

| Field | Default | Description |
|---|---|---|
| `queue_depth` | 1000 | Max queued requests per backend |
| `jitter_factor` | 0.05 | Weight jitter factor (0.0–1.0) |
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
| `level` | 3 | Zstd compression level (1–22) |
| `min_bytes` | 256 | Skip compression below this body size |

## `[proxy]`

| Field | Default | Description |
|---|---|---|
| `max_response_body_bytes` | 10 MB | Maximum response body size |
| `h2_connections_per_backend` | 4 | HTTP/2 connections per backend |
| `max_idle_quic_per_host` | 16 | Idle QUIC connections per host |
| `h2_stream_window` | 2 MB | HTTP/2 per-stream flow control window |
| `h2_conn_window` | 4 MB | HTTP/2 per-connection flow control window |
| `inline_compress_threshold` | 8192 | Bodies at or below this size compress inline; larger ones use a blocking task |
| `quic_channel_capacity` | 256 | Bounded channel size for QUIC stream accept queue |

## `[tracing]`

| Field | Default | Description |
|---|---|---|
| `otlp_endpoint` | none | OTLP HTTP endpoint for trace export |
| `sample_ratio` | 1.0 | Trace sampling ratio (0.0–1.0) |

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
| `host` | no | IP from address | Host header / SNI value |
| `pool` | no | same as `id` | Pool grouping key |
| `max_connections` | no | 256 | Max concurrent connections to this backend |

## `[[routes]]`

| Field | Required | Default | Description |
|---|---|---|---|
| `path_prefix` | yes | — | URL path prefix (longest match wins) |
| `backend_id` | yes | — | Target backend `id` |
| `timeout_secs` | no | global `request_secs` | Per-route request timeout override |
