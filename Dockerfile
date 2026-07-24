FROM rust:1.77-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libssh2-1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/veltrix /usr/local/bin/veltrix

RUN useradd -r -s /bin/false veltrix || true

ENTRYPOINT ["veltrix"]
CMD ["--help"]
