FROM rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS build
WORKDIR /build
COPY signer/Cargo.toml signer/Cargo.lock signer/build.rs ./
COPY signer/proto ./proto
COPY signer/src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:66aa873a4a14fb164aa01296058efd8253744606d72715e45acface073359faa
ARG BUILD_MEASUREMENT=development-unmeasured
ENV AEGIS_SIGNER_BUILD_MEASUREMENT=${BUILD_MEASUREMENT}
COPY --from=build /build/target/release/aegisledger-signer /usr/local/bin/aegisledger-signer
USER nonroot:nonroot
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/aegisledger-signer"]
