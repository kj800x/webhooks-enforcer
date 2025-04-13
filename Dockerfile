# Build Stage
FROM rust:1.85-alpine AS builder
WORKDIR /usr/src/
# Install required build dependencies
RUN apk update && \
  apk add --no-cache \
  musl-dev \
  pkgconf \
  openssl-dev \
  build-base \
  openssl-libs-static

# - Install dependencies
RUN USER=root cargo new webhooks-enforcer
WORKDIR /usr/src/webhooks-enforcer
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

# - Copy source
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime Stage
FROM alpine:latest AS runtime
WORKDIR /app
# Install runtime dependencies if needed
# RUN apk add --no-cache ca-certificates

COPY --from=builder /usr/src/webhooks-enforcer/target/release/webhooks-enforcer ./webhooks-enforcer
USER 1000
CMD ["./webhooks-enforcer"]
