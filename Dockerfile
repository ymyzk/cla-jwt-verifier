FROM ekidd/rust-musl-builder:stable AS builder

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release


FROM scratch

COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/cla-jwt-verifier /

CMD ["/cla-jwt-verifier"]
EXPOSE 3030
