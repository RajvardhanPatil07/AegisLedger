# Isolated signer

This service is the only component that creates or holds the secp256k1 signing
key. Its gRPC surface has two operations: read the public identity and sign an
exact EIP-1559 payload accompanied by a valid, unexpired, single-use policy
decision. There is no arbitrary-message signing operation and no key export.

Every signing request is checked again inside the process for policy-service
signature, proposal hash, policy hash, reservation, wallet, chain, monotonic
nonce, intent fields, expiry, and typed-data binding. The signer decodes the
canonical EIP-1559 RLP and compares its chain, nonce, target, value, calldata,
gas, and fees with the authorized structured transaction. It returns canonical
EIP-2718 signed bytes and the network transaction hash. mTLS client
authentication is mandatory.

Startup fails closed unless `AEGIS_SIGNER_PRIVATE_KEY_FILE` points to a
non-writable secret file and `AEGIS_SIGNER_REPLAY_STATE_FILE` points to durable
storage. Replay decisions and wallet nonce watermarks are atomically persisted
before a signature is produced. The local container and Nitro Enclave image
use the same binary, but the Compose key file is development-only. Production
must inject key material through an enclave/HSM-aware secret provider and must
not expose it to the API or host application. Rotation and recovery procedures
live in `docs/runbooks/signer-key-management.md`.
