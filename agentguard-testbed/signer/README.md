# Isolated signer

This service is the only component that creates or holds the secp256k1 signing
key. Its gRPC surface has two operations: read the public identity and sign an
exact EIP-1559 payload accompanied by a valid, unexpired, single-use policy
decision. There is no arbitrary-message signing operation and no key export.

Every signing request is checked again inside the process for policy-service
signature, proposal hash, policy hash, reservation, wallet, chain, monotonic
nonce, intent fields, expiry, EIP-712 digest, and EIP-1559 digest. mTLS client
authentication is mandatory.

The local container and Nitro Enclave image use the same binary. Production
key persistence must use an enclave-bound KMS ciphertext; a host-readable seed
is intentionally unsupported. Rotation and recovery procedures live in
`docs/runbooks/signer-key-management.md`.

