# Signer key and replay-state runbook

This runbook separates the disposable local workflow from production key
custody. The API never receives wallet private-key material.

## Local development

`make bootstrap` creates an ignored 32-byte secp256k1 key at
`artifacts/dev-signer/signer-private-key.hex`. Compose exposes it only to the
signer as `/run/secrets/signer-private-key`. The `signer-state` volume preserves
consumed decision identifiers and wallet nonce watermarks across restarts.
Bootstrap derives the corresponding address and writes an ignored development
policy under `artifacts/dev-policy`; this prevents the policy wallet from
drifting away from the actual signer identity.

Do not copy this development key into staging or production. Removing the
`signer-state` volume is a destructive reset: any chain wallet that keeps the
same key must be reconciled to a new nonce watermark before it signs again.

## Production requirements

1. Generate the key inside the approved HSM, enclave, or custody boundary.
2. Deliver the key to `AEGIS_SIGNER_PRIVATE_KEY_FILE` through the platform
   secret mechanism; never use an environment variable or image layer.
3. Mount `AEGIS_SIGNER_REPLAY_STATE_FILE` on encrypted, durable storage with a
   single writer and backups. The signer atomically records consumption before
   signing.
4. Pin the expected signer identity and build measurement in deployment
   configuration, then verify `PublicIdentity` over mTLS before enabling
   proposal intake.
5. Deny all signer network paths except the authenticated API client and the
   required custody endpoint.

The reference binary reads a protected key file. A deployment claiming
hardware-backed non-exportability must add and independently assess the
platform-specific KMS/HSM adapter; the reference repository does not claim
that property by itself.

## Rotation

1. Stop new proposals and allow submitted transactions to reconcile.
2. Back up the replay-state file and record its SHA-256 digest, the audit head,
   the old signer identity, and the last chain nonce for every managed wallet.
3. Provision a new key inside the custody boundary and update the managed
   wallet or account-abstraction authorization through its governed process.
4. Start the signer with a fresh replay-state path and the new key. Verify the
   reported identity and an offline test transaction on a non-production chain.
5. Update the approved identity/measurement, restore traffic gradually, and
   retain the old key disabled for the documented recovery window.

Never reuse an old replay-state file with a different signer identity, and
never reset replay state while retaining a live wallet key without explicit
chain-nonce reconciliation.

## Suspected compromise

Immediately stop proposal intake, isolate the signer, preserve replay state and
audit evidence, revoke the signer from the wallet control plane, and rotate the
key. Reconcile every authorization and receipt since the earliest suspected
compromise time. Resume only after independent review of custody logs, build
measurement, replay-state continuity, and chain state.
