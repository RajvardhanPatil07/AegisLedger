# AWS Nitro Enclave deployment reference

Build the signer container reproducibly, convert it to an EIF with
`nitro-cli build-enclave`, record PCR0/PCR1/PCR2 in the deployment allowlist,
and launch it with the CPU, memory, CID, and port in
`enclave-config.example.json`. The parent instance may run only a narrow mTLS
to-vsock relay; it must not expose a generic byte-forwarding or signing API.

The enclave obtains a KMS ciphertext through the relay and calls KMS Decrypt
with an attestation document whose PCRs match the key policy. Plaintext key
material is created inside enclave memory and never returned through vsock.
The response evidence must include the Nitro attestation document, signer
public identity, request decision nonce, and signer build measurement.

This directory is a deployment reference for local/testnet research. It does
not enable mainnet custody.

