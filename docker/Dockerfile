# syntax=docker/dockerfile:1

# PhoneConnect server image: the control plane, rendezvous service, and relay in one
# process. Runtime traffic is PhoneConnect framing only; nothing here exposes ADB.

# The one UI is built here and served by the server, so the image ships exactly the bundle a
# browser and the native shell load from `<server>/`.
FROM node:24-bookworm-slim AS web

WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web ./
RUN npm run build

FROM rust:1.100-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY server ./server

RUN cargo build --release --locked --bin phoneconnect-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin phoneconnect \
    && mkdir -p /data \
    && chown phoneconnect:phoneconnect /data

COPY --from=builder /build/target/release/phoneconnect-server /usr/local/bin/phoneconnect-server
COPY --from=web /build/web/dist /app/web

USER phoneconnect
WORKDIR /data

ENV PHONECONNECT_LISTEN_ADDR=0.0.0.0:8080 \
    PHONECONNECT_DATABASE_PATH=/data/phoneconnect.sqlite3 \
    PHONECONNECT_RELAY_ENDPOINT=http://localhost:8080/api/sessions \
    PHONECONNECT_WEB_ROOT=/app/web

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/phoneconnect-server"]
