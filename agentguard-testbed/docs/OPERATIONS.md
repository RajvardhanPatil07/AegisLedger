# Operations runbook

This runbook covers the local/reference Compose deployment. It is suitable for
reproducible research and pre-production validation, not direct internet
exposure. Production must replace Keycloak start-dev, local generated
credentials, and single-node PostgreSQL with managed, TLS-enabled services.

## Start and verify

~~~sh
make bootstrap
docker compose --env-file .env.local up --build --detach
docker compose --env-file .env.local ps
curl -fsS http://127.0.0.1:${AEGIS_API_PORT:-8000}/health/ready
curl -fsS http://127.0.0.1:${AEGIS_WEB_PORT:-4173}/
curl -fsS http://127.0.0.1:9000/health/ready
curl -fsS http://127.0.0.1:9090/-/ready
~~~

All published ports bind to loopback. Open the console at
http://localhost:${AEGIS_WEB_PORT:-4173}; use `localhost`, rather than its
numeric loopback address, because the development OIDC redirect URI is exact.
Set AEGIS_API_PORT or AEGIS_WEB_PORT when a default port is already in use. The
API is ready only after the database is reachable and an active policy exists.

## Backup and restore drill

Create a mode-0600 custom-format PostgreSQL backup:

~~~sh
make backup
~~~

Verify a backup without overwriting the live database:

~~~sh
make verify-backup BACKUP=artifacts/backups/aegisledger-YYYYMMDDTHHMMSSZ.dump
~~~

The drill restores into a uniquely named temporary database, checks the
application schema, and drops only that temporary database. Store production
backups encrypted outside the deployment account and test recovery at least
monthly. Restore-time and recovery-point objectives are deployment-specific and
must be recorded before launch.

## Alerts

Prometheus loads deploy/prometheus/alerts.yml. Route critical alerts to the
primary on-call and warning alerts to the service channel. The reference
deployment fires on API/identity-provider unavailability, sustained 5xx rates
above 5%, and sustained p95 latency above one second.

### API or identity provider unavailable

1. Confirm impact from two locations and check /health/ready.
2. Inspect docker compose logs for API, Keycloak, and PostgreSQL.
3. Stop proposal intake if authorization or identity state is uncertain.
4. Preserve logs, current image digests, policy hash, and audit head.
5. Restart only the failed stateless service. Do not reset PostgreSQL volumes.
6. If recovery fails, execute the rollback procedure below.

### Elevated API error rate or latency

1. Split metrics by route and status; correlate with PostgreSQL and Keycloak.
2. Check saturation, connection failures, and recent policy or image changes.
3. Rate-limit new experiment runs before authorization traffic.
4. Roll back if the increase began with the current release.

### Suspected authorization or key compromise

1. Disable proposal intake and isolate the signer network path.
2. Revoke affected OIDC sessions and rotate signing material through the
   deployment secret manager.
3. Preserve the append-only audit stream, attestation roots, image digest, and
   policy artifacts before remediation.
4. Treat all decisions issued after the earliest suspected compromise time as
   untrusted and reconcile them against chain receipts.
5. Resume only after independent attestation and audit-chain verification.

## Rollback

1. Record the failing image digests, migration revision, active policy hash, and
   audit head.
2. Stop new proposal intake; allow already-submitted chain transactions to
   reconcile.
3. Select the last release whose CI, formal model, container scan, and runtime
   smoke checks passed.
4. Confirm its database migration is backward compatible. Never downgrade a
   schema by deleting a volume.
5. Redeploy prior immutable images, verify readiness, OIDC, and Prometheus, then
   submit a synthetic zero-value policy simulation.
6. Re-enable traffic gradually and retain the incident artifacts.

If a migration is not backward compatible, restore into a new PostgreSQL
instance from the last verified backup, validate audit continuity, and switch
traffic only after reconciliation. Do not overwrite the impaired database.

## Shutdown

make down keeps named volumes. docker compose down --volumes deletes local state
and is reserved for disposable CI environments.
