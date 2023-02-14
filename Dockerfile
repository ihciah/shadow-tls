FROM rust:1.67-alpine as builder
WORKDIR /usr/src/shadow-tls
RUN apk add --no-cache musl-dev libressl-dev

COPY . .
RUN RUSTFLAGS="" cargo build --bin shadow-tls --release

FROM alpine:latest

ENV MODE=""
ENV LISTEN=""
ENV SERVER=""
ENV TLS=""
ENV THREADS=""
ENV PASSWORD=""
ENV ALPN=""
ENV DISABLE_NODELAY=""
ENV V3=""
ENV STRICT=""

COPY ./entrypoint.sh /
RUN chmod +x /entrypoint.sh && apk add --no-cache ca-certificates
COPY --from=builder /usr/src/shadow-tls/target/release/shadow-tls /usr/local/bin/shadow-tls
ENTRYPOINT ["/entrypoint.sh"]