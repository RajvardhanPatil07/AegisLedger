FROM aegisledger-signer:local

# Nitro Enclaves has no external network. The parent-instance relay terminates
# mTLS and forwards only the signer protobuf protocol over vsock.
ENV AEGIS_SIGNER_BIND=0.0.0.0:50051
ENTRYPOINT ["/usr/local/bin/aegisledger-signer"]

