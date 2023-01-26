# Add another layer just to fetch Cargo on the build platform.
# This is to work around this issue with QEMU on ARMv7: https://github.com/docker/buildx/issues/395
# More details: https://gitlab.com/qemu-project/qemu/-/issues/263 and https://github.com/rust-lang/cargo/issues/8719
FROM --platform=$BUILDPLATFORM rust:1.66.1-slim-buster as sources

WORKDIR /usr/src/shadow-tls
RUN cargo init
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
RUN mkdir -p ./.cargo \
  && cargo vendor > ./.cargo/config

FROM rust:1.66.1-slim-buster as builder

WORKDIR /usr/src/shadow-tls

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
   build-essential \
   libssl-dev;


COPY ./ ./
COPY --from=sources /usr/src/shadow-tls/.cargo ./.cargo
COPY --from=sources /usr/src/shadow-tls/vendor ./vendor

RUN RUSTFLAGS="" cargo build --bin shadow-tls --release --offline

FROM alpine:latest

ENV MODE=""
ENV LISTEN=""
ENV SERVER=""
ENV TLS=""
ENV THREADS=""
ENV PASSWORD=""
ENV DISABLE_NODELAY=""

COPY ./entrypoint.sh /
RUN chmod +x /entrypoint.sh && apk add --no-cache ca-certificates
COPY --from=builder /usr/src/shadow-tls/target/release/shadow-tls /usr/local/bin/shadow-tls
ENTRYPOINT ["/entrypoint.sh"]