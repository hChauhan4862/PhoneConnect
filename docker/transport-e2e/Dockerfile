# syntax=docker/dockerfile:1

# Stub image for the transport end-to-end test. It builds only the `path-stub` binary: a
# client stub and a device stub run from this one image with different environment.

FROM rust:1.100-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY server ./server
COPY native ./native

RUN cargo build --release --locked --bin path-stub

FROM debian:bookworm-slim AS runtime

RUN useradd --system --uid 10001 --shell /usr/sbin/nologin phoneconnect
COPY --from=builder /build/target/release/path-stub /usr/local/bin/path-stub

USER phoneconnect
ENTRYPOINT ["/usr/local/bin/path-stub"]
