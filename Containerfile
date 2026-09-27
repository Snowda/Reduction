# syntax=docker/dockerfile:1
# Multi-stage build for the reduction M2M reverse proxy.
# Build:  podman build -t reduction -f Containerfile .
# Run:    podman run --rm -p 8443:8443/udp \
#             -v ./config.toml:/etc/reduction/config.toml:ro,Z \
#             -v ./certs:/etc/reduction/certs:ro,Z \
#             reduction
# The single positional argument is the config path; override the default by
# appending your own path: `podman run ... reduction /etc/reduction/other.toml`.

# ---- build stage ----
FROM docker.io/library/rust:1.96-bookworm AS build
WORKDIR /src

# aws-lc-sys (rustls' default aws-lc-rs crypto backend) builds its C sources via
# cmake at compile time; the rust image ships gcc and perl but not cmake.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

# Build the reduction binary only (the manifest also declares examples and
# benches we do not ship). Registry, git, and target dirs are cache mounts so
# repeat builds reuse compiled dependencies; the finished binary is copied out
# of the ephemeral target mount before the layer ends.
COPY . .
# Build with the `acme` feature so the released image can self-provision Let's Encrypt / ACME
# certificates (tls-alpn-01) — the public-facing deployment depends on it. `--locked` pins the
# resolved Cargo.lock so the image is reproducible.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --features acme --bin reduction \
    && cp target/release/reduction /usr/local/bin/reduction

# ---- runtime stage ----
FROM docker.io/library/debian:bookworm-slim AS runtime

# ca-certificates lets ACME/Let's Encrypt reach public issuer endpoints; tzdata
# keeps log timestamps sane. Everything else is statically covered by glibc.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user.
RUN useradd --system --create-home --uid 10001 app
RUN mkdir -p /etc/reduction && chown app:app /etc/reduction
USER app

COPY --from=build /usr/local/bin/reduction /usr/local/bin/reduction

# QUIC ingress is UDP; the TCP transport option shares the port. For the public-browser edge
# deployment, the listener binds 443 (TLS) and the optional redirect listener binds 80 — documented
# here for that use. EXPOSE is advisory only; actual ports come from the config and `podman run -p`.
EXPOSE 8443/udp
EXPOSE 8443/tcp
EXPOSE 443/tcp
EXPOSE 80/tcp

ENTRYPOINT ["/usr/local/bin/reduction"]
CMD ["/etc/reduction/config.toml"]
