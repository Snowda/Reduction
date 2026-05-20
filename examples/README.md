# Examples

## acl_demo

Demonstrates Reduction's CIDR-based IP access control (allow/deny listing). Starts a proxy with four different ACL configurations in sequence and shows how each mode handles incoming requests:

1. **Allow-list only** — default-deny, only listed CIDRs pass (127.0.0.1/32 allowed)
2. **Deny-list only** — default-allow, listed CIDRs blocked (10.0.0.0/8 denied)
3. **Both lists** — deny checked first, then allow, default-deny (127.0.0.1 denied even though it falls within the allow range)
4. **Disabled** — no rules configured, all traffic passes through

```sh
cargo run --example acl_demo
```

## demo

A self-contained demonstration of Reduction's core proxy features: mTLS certificate generation, request forwarding, health-weighted backend selection, and config hot-reload. Starts a simple JSON echo backend behind the proxy and exercises each feature in sequence.

```sh
cargo run --example demo
```

## mcp_demo

Demonstrates Reduction as a reverse proxy in front of MCP (Model Context Protocol) servers, using full mTLS authentication throughout.

### What it does

The demo spins up all components in a single process — no external dependencies or manual setup required.

```
┌──────────────┐       mTLS/TCP       ┌───────────┐      mTLS/TCP      ┌──────────────┐
│  Rust MCP    │ ───────────────────►  │ Reduction │ ────────────────►  │  MCP Server  │
│  Client      │  POST /mcp           │   Proxy   │                    │  Backend A   │
│              │  (JSON-RPC)           │  :18443   │                    │  :19443      │
└──────────────┘                       └───────────┘ ────────────────►  ├──────────────┤
                                                                        │  MCP Server  │
                                                                        │  Backend B   │
                                                                        │  :19444      │
                                                                        └──────────────┘
```

The demo runs four phases:

**Phase 1 — TLS certificates.** Generates an ephemeral CA, server certificate (SAN: 127.0.0.1), and client certificate using `rcgen`. All files are written to a temp directory and cleaned up on exit.

**Phase 2 — MCP data plane.** Starts two MCP server backends that handle three JSON-RPC methods:

| Method | Description |
|---|---|
| `initialize` | Returns server capabilities and info |
| `tools/list` | Returns available tools (`echo`, `add`) |
| `tools/call` | Executes `echo` (returns input) or `add` (sums two numbers) |

A Rust client sends MCP requests through the Reduction proxy using mTLS. Each response includes a `_backend` field identifying which server handled it. A batch of 10 requests shows rendezvous hashing's deterministic client affinity — all requests from the same IP consistently route to the same backend.

**Phase 3 — Health-aware failover.** Pushes health state updates to the proxy's control plane:
1. Marks backend A as heavily loaded (0.95) — traffic shifts toward backend B
2. Marks backend A as unavailable — all traffic fails over to backend B

**Phase 4 — Config hot-reload.** Writes a new `/mcp/v2` route to the config file. After the file watcher detects the change (~2 seconds), the demo confirms the new route works alongside the original `/mcp` route, without any restart.

### Run it

```sh
cargo run --example mcp_demo
```

### Expected output

```
Reduction - MCP Reverse Proxy Demo
===================================

-- Phase 1: TLS Certificate Generation --

  [ok] CA certificate
  [ok] Server certificate (SAN: 127.0.0.1)
  [ok] Client certificate (mTLS)

-- Phase 2: MCP Data Plane --

  Backend A (:19443), Backend B (:19444), Proxy (:18443) started

  --- MCP initialize ---
  -> 200 OK {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26",...}}

  --- MCP tools/call (echo) ---
  -> 200 OK {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"hello from M2M client"}],...}}

  --- MCP tools/call (add) ---
  -> 200 OK {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"42"}],...}}

  --- Load balancing (10 requests, same client IP) ---
  mcp-backend-b: 10 requests

-- Phase 3: Health-Aware Failover --

  Pushed health update: mcp-a loaded (0.95), mcp-b healthy (0.1)
  After health update (10 requests):
    mcp-backend-b: 10 requests

  Pushed health update: mcp-a DOWN, mcp-b healthy
  After failover (10 requests):
    mcp-backend-b: 10 requests

-- Phase 4: Config Hot-Reload --

  Config updated: added /mcp/v2 route
  POST /mcp/v2 tools/list -> 200 OK {...}
  POST /mcp    tools/list -> 200 OK {...}

-- Demo Complete --
```

## profile_loadtest

Configurable load driver for profiling and flamechart analysis. Starts the same mTLS proxy + backend setup as the demos, then drives sustained traffic at configurable concurrency and reports latency percentiles.

### Usage

```sh
# 10 concurrent workers, 1000 total requests (defaults)
cargo run --release --example profile_loadtest

# Custom: 20 workers, 5000 requests
cargo run --release --example profile_loadtest -- 20 5000

# With chrome trace output (opens in https://ui.perfetto.dev)
cargo run --release --example profile_loadtest -- 10 500 --trace
```

The `--trace` flag writes a `trace.json` to the working directory. Open it in [Perfetto UI](https://ui.perfetto.dev) to see a per-request flamechart with spans for each proxy phase: rate limit check, route matching, backend selection, connection pool acquire, and request forwarding.

### Sampling flamegraph

For CPU-level profiling, install `cargo-flamegraph` and run with ETW (requires admin):

```sh
cargo install flamegraph
cargo flamegraph --release --example profile_loadtest -- 20 5000
```

This produces an interactive SVG flamegraph showing where CPU time is spent.

### Notes

- **Client affinity:** All demo requests originate from `127.0.0.1`, so rendezvous hashing deterministically routes them to one backend. In production with diverse client IPs, requests distribute across backends proportional to their weights.
- **No compression negotiation:** The MCP client does not send `Accept-Encoding: zstd`, so responses pass through the proxy uncompressed. This also means SSE streaming (used by MCP's Streamable HTTP transport) would work without buffering, since the proxy only collects the full body when compressing.
- **Ports:** The demo uses ports 18443, 19443, and 19444. If these conflict with existing services, the constants at the top of `mcp_demo.rs` can be changed.
