FROM rust:1.97.1-bookworm AS build
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY signer/Cargo.toml signer/Cargo.lock signer/build.rs ./
COPY signer/proto ./proto
COPY signer/src ./src
RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12:nonroot
ARG BUILD_MEASUREMENT=development-unmeasured
ENV AEGIS_SIGNER_BUILD_MEASUREMENT=${BUILD_MEASUREMENT}
COPY --from=build /build/target/release/aegisledger-signer /usr/local/bin/aegisledger-signer
USER nonroot:nonroot
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/aegisledger-signer"]
