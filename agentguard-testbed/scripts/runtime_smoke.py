#!/usr/bin/env python3
"""Prove proposal-to-settlement execution against the running Compose services."""

from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime, timedelta

import httpx
import psycopg

from aegisledger.api import ExecutionRequest
from aegisledger.attestations import verify_complete_attestation
from aegisledger.canonical import uuid7
from aegisledger.contracts import LifecycleState, ProposalV1, TransferIntentV1
from aegisledger.main import build_services
from aegisledger.settings import Settings

PRINCIPAL = "00000000-0000-4000-8000-000000000101"
RECIPIENT = "0x3434343434343434343434343434343434343434"


def rpc(client: httpx.Client, url: str, method: str, params: list[object]) -> object:
    response = client.post(
        url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("error") is not None:
        raise RuntimeError(f"RPC method failed: {method}")
    if "result" not in payload:
        raise RuntimeError(f"RPC method omitted its result: {method}")
    return payload["result"]


def close_services(services: object) -> None:
    signer = getattr(services, "signer", None)
    close_signer = getattr(signer, "close", None)
    if callable(close_signer):
        close_signer()
    for backend in getattr(services, "chain_backends", {}).values():
        close_backend = getattr(backend, "close", None)
        if callable(close_backend):
            close_backend()


def durable_next_nonce(settings: Settings, wallet: str) -> int:
    if settings.database_url is None:
        return 0
    with psycopg.connect(settings.database_url) as connection:
        row = connection.execute(
            """SELECT GREATEST(
                   COALESCE((SELECT MAX(wallet_nonce) FROM transactions
                             WHERE wallet=%s AND chain_id=%s), -1),
                   COALESCE((SELECT MAX(nonce) FROM wallet_nonce_uses
                             WHERE wallet=%s AND chain_id=%s), -1)
               ) + 1""",
            (wallet, settings.rpc_chain_id, wallet, settings.rpc_chain_id),
        ).fetchone()
    if row is None:
        raise RuntimeError("durable nonce query returned no row")
    return int(row[0])


def main() -> int:
    settings = Settings()  # type: ignore[call-arg]
    if settings.rpc_url is None:
        raise RuntimeError("runtime smoke requires AEGIS_RPC_URL")
    services = build_services(settings)
    try:
        if services.signer is None or services.settlement_reconciler is None:
            raise RuntimeError("runtime smoke requires signer and settlement reconciliation")
        signer_identity = services.signer.identity().signer_identity.lower()
        with httpx.Client(timeout=settings.rpc_timeout_seconds) as client:
            rpc(client, settings.rpc_url, "anvil_setBalance", [signer_identity, hex(10**20)])
            nonce_raw = rpc(
                client,
                settings.rpc_url,
                "eth_getTransactionCount",
                [signer_identity, "pending"],
            )
            if not isinstance(nonce_raw, str):
                raise RuntimeError("RPC returned a malformed wallet nonce")
            wallet_nonce = max(int(nonce_raw, 16), durable_next_nonce(settings, signer_identity))
            if wallet_nonce != int(nonce_raw, 16):
                rpc(
                    client,
                    settings.rpc_url,
                    "anvil_setNonce",
                    [signer_identity, hex(wallet_nonce)],
                )

        proposal = ProposalV1(
            schema_version="aegisledger.proposal.v1",
            proposal_id=uuid7(),
            principal_id=PRINCIPAL,
            wallet=signer_identity,
            chain_id=settings.rpc_chain_id,
            asset=f"NATIVE:{settings.rpc_chain_id}",
            amount=100,
            intent=TransferIntentV1(kind="transfer", recipient=RECIPIENT),
            deadline=datetime.now(UTC) + timedelta(minutes=2),
            idempotency_key=f"runtime-smoke-{uuid7()}",
        )
        submission = services.submit(proposal, PRINCIPAL)
        if submission.state is not LifecycleState.RESERVED:
            raise AssertionError(f"proposal was not reserved: {submission.state.value}")
        execution = services.execute(
            proposal.proposal_id,
            ExecutionRequest(
                wallet_nonce=wallet_nonce,
                value=proposal.amount,
                gas_limit=21_000,
                max_fee_per_gas=2_000_000_000,
                max_priority_fee_per_gas=1_000_000_000,
            ),
            PRINCIPAL,
        )
        if not execution.submitted:
            raise AssertionError("signed transaction was not submitted")

        timeout_at = time.monotonic() + 30
        record = services.state.get(proposal.proposal_id)
        while time.monotonic() < timeout_at:
            services.settlement_reconciler.poll_once()
            record = services.state.get(proposal.proposal_id)
            if record is not None and record.state in {
                LifecycleState.SETTLED,
                LifecycleState.REVERTED,
            }:
                break
            time.sleep(0.5)
        else:
            raise TimeoutError("transaction did not reach terminal finality")
        assert record is not None
        if record.state is not LifecycleState.SETTLED:
            raise AssertionError(f"transaction did not settle successfully: {record.state.value}")

        attestation = services.complete_attestation(proposal.proposal_id, PRINCIPAL)
        report = verify_complete_attestation(
            attestation,
            services.decisions.public_key,
            allowed_build_measurements=services.allowed_build_measurements,
        )
        if not report.valid:
            raise AssertionError(f"offline attestation verification failed: {report.errors}")
        print(
            json.dumps(
                {
                    "attestation_valid": report.valid,
                    "confirmations": attestation.settlement.confirmations,
                    "lifecycle_state": attestation.lifecycle_state,
                    "proposal_id": str(proposal.proposal_id),
                    "signer_identity": signer_identity,
                    "signing_hash": execution.signing_hash,
                    "transaction_hash": execution.transaction_hash,
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        close_services(services)


if __name__ == "__main__":
    sys.exit(main())
