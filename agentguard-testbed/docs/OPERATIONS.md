# Operations runbook

This runbook covers the loopback-only local/reference Compose profile. Do not
expose it directly to the internet or use real funds. Production must replace
development identity, local secrets, file-backed signing state, single-node
PostgreSQL, and local-chain assumptions.

## Start and readiness

```bash
make bootstrap
docker compose --env-file .env.local up --build --detach
docker compose --env-file .env.local ps
curl -fsS http://127.0.0.1:${AEGIS_API_PORT:-8000}/health/ready
curl -fsS http://127.0.0.1:${AEGIS_WEB_PORT:-4173}/
curl -fsS http://127.0.0.1:9000/health/ready
curl -fsS http://127.0.0.1:9090/-/ready
```

Use `localhost` for the console because the development OIDC redirect URI is
exact. Override `AEGIS_API_PORT` and `AEGIS_WEB_PORT` when the defaults are in
use. All published ports bind to loopback.

API readiness verifies:

- proposal/policy PostgreSQL access;
- authorization artifacts and complete attestations;
- append-only audit journal;
- durable experiment jobs and rate windows;
- an active policy;
- isolated signer identity over mTLS when configured.

Readiness does not prove that an RPC provider will accept a future transaction.
Use the runtime proof for that.

## End-to-end runtime proof

```bash
docker compose --env-file .env.local exec --no-TTY \
  api python /app/scripts/runtime_smoke.py
```

The harness funds only the generated signer account on Anvil, restores Anvil's
local nonce from durable transaction history after a chain-container restart,
submits a 100-wei allowlisted transfer, waits for configured finality, assembles
the persisted complete attestation, and verifies it offline. A fresh environment
starts at nonce zero. A signer/database divergence remains fail closed and
requires reconciliation.

## Normal inspection

```bash
docker compose --env-file .env.local logs --tail=200 api signer postgres anvil
docker compose --env-file .env.local exec --no-TTY postgres \
  psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --command "select state,count(*) from proposals group by state order by state"
```

Do not print `.env.local`, private-key files, bearer tokens, or full request
bodies into incident logs. Retain proposal IDs, decision IDs, signing/network
hashes, policy hashes, image digests, audit head, and canonical receipts.

## Backup and restore drill

Create a mode-0600 PostgreSQL custom-format backup:

```bash
make backup
```

Verify it without overwriting the live database:

```bash
make verify-backup BACKUP=artifacts/backups/aegisledger-YYYYMMDDTHHMMSSZ.dump
```

The verifier restores into a uniquely named temporary database, checks the
application schema, and drops only that temporary database. Production backups
must be encrypted outside the deployment account and exercised against defined
RPO/RTO values. This repository does not set those deployment-specific values.

## Ambiguous signing operation

Use this procedure when the signer may have consumed a decision but the API did
not retain a signed execution:

1. Stop new proposal execution; keep read and reconciliation paths available.
2. Record proposal/decision/reservation IDs, wallet, chain, nonce, signer
   identity, signer replay-state version, audit head, and relevant logs.
3. Query retained transactions and wallet/decision nonce-use tables.
4. Query the chain by expected wallet/nonce and any retained transaction hash.
5. Never delete replay state or reissue the same decision to regain liveness.
6. If raw signed bytes are recoverable and bindings verify, persist/reconcile
   through an independently reviewed repair procedure. Otherwise expire the
   reservation and advance the wallet nonce through the custody runbook.
7. Record the resolution as an incident and test the exact failure boundary.

## Alerts and response

Prometheus loads `deploy/prometheus/alerts.yml`. The reference rules cover API
and identity-provider unavailability, sustained 5xx rates above 5%, and
sustained p95 latency above one second. Production routing and thresholds must
match measured SLOs.

### Authorization, audit, or key compromise

1. Disable proposal intake and isolate the signer network path.
2. Preserve signer state, PostgreSQL, audit head, policy artifacts, canonical
   receipts, images, SBOMs, and logs before remediation.
3. Revoke affected OIDC sessions and rotate credentials using the deployment
   secret/custody system; do not bootstrap over retained evidence.
4. Treat decisions after the earliest suspected compromise as untrusted and
   reconcile each against chain state.
5. Resume only after audit-chain and signer-state continuity are independently
   verified.

### Elevated errors or latency

1. Split metrics by route/status and correlate PostgreSQL, Keycloak, signer, RPC,
   and experiment workloads.
2. Rate-limit or pause experiments before authorization traffic.
3. Check the latest policy, migration, dependency, and image changes.
4. Roll back if the regression began with the current release.

## Rollback

1. Stop new proposal intake; continue reconciliation for submitted transactions.
2. Record failing image digests, migration revision, active policy hash, audit
   head, and pending lifecycle states.
3. Select the last release whose CI, formal, security, SBOM, and full runtime
   smoke gates passed for one commit.
4. Confirm schema compatibility. Never roll back by deleting a volume.
5. Redeploy immutable prior images, verify readiness/OIDC/metrics, and run a
   policy simulation plus a scoped runtime proof.
6. Re-enable traffic gradually and retain incident artifacts.

If a migration is not backward compatible, restore a verified backup into a new
PostgreSQL instance, validate audit continuity and chain reconciliation, and
switch only after review. Do not overwrite the impaired database.

## Shutdown

`make down` retains named volumes. `docker compose down --volumes` deletes local
state and is only appropriate for a known disposable CI/reviewer project.
