FROM ekidd/rust-musl-builder:stable AS builder

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release


FROM alpine:latest

RUN apk add --no-cache ca-certificates tini
COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/cla-jwt-verifier /

USER nobody
ENTRYPOINT ["/sbin/tini", "/cla-jwt-verifier"]
EXPOSE 3030
