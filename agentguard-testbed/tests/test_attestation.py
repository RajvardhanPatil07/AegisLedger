"""Attestation integrity: verification succeeds for genuine attestations and
fails for any tampering — the core assurance property."""

import dataclasses

from agentwallet.guard.attestation import EnclaveAttestor, verify_attestation
from agentwallet.guard.engine import Proposal
from agentwallet.guard.policy import load_policy


def make():
    att = EnclaveAttestor("test", now=lambda: 1234)
    pol = load_policy("name: p\nper_tx_cap: 100\n")
    p = Proposal(kind="transfer", amount=50, to="0xaaa")
    a = att.attest(pol.hash(), p.canonical(), "ALLOW", [])
    return att, a


def test_genuine_attestation_verifies():
    att, a = make()
    assert verify_attestation(a, att.public_key)


def test_tampered_verdict_fails():
    att, a = make()
    forged = dataclasses.replace(a, verdict="DENY")
    assert not verify_attestation(forged, att.public_key)


def test_tampered_policy_hash_fails():
    att, a = make()
    forged = dataclasses.replace(a, policy_hash="0" * 64)
    assert not verify_attestation(forged, att.public_key)


def test_tampered_proposal_hash_fails():
    att, a = make()
    forged = dataclasses.replace(a, proposal_hash="f" * 64)
    assert not verify_attestation(forged, att.public_key)


def test_wrong_enclave_key_fails():
    att, a = make()
    other = EnclaveAttestor("other", now=lambda: 1234)
    assert not verify_attestation(a, other.public_key)


def test_attestation_binds_exact_proposal():
    att, a = make()
    p2 = Proposal(kind="transfer", amount=51, to="0xaaa")  # different amount
    a2 = att.attest(a.policy_hash, p2.canonical(), "ALLOW", [])
    assert a.proposal_hash != a2.proposal_hash
    assert verify_attestation(a2, att.public_key)
