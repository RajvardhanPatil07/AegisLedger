"""AgentGuard: the reference-monitor pipeline.

    agent proposal -> PolicyEngine.evaluate -> EnclaveAttestor.attest
                   -> (on ALLOW) IsolatedSigner.sign -> chain settlement

Every decision is appended to a hash-chained audit log: each entry commits to
the previous entry's hash, so post-hoc log tampering is detectable.

The guard is the *only* path to the signer. Agents hold a GuardClient handle
that exposes `submit` and nothing else.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .engine import PolicyEngine, Proposal, Verdict
from .attestation import EnclaveAttestor, Attestation
from ..wallet.signer import IsolatedSigner
from ..chain.crypto import sha256_hex
from ..chain.ledger import LocalChain, Tx, TxKind


@dataclass
class AuditEntry:
    seq: int
    prev_hash: str
    proposal: dict
    verdict: str
    attestation_sig: str
    settled: bool

    def hash(self) -> str:
        d = {"seq": self.seq, "prev_hash": self.prev_hash, "proposal": self.proposal,
             "verdict": self.verdict, "attestation_sig": self.attestation_sig,
             "settled": self.settled}
        return sha256_hex(json.dumps(d, sort_keys=True, separators=(",", ":")).encode())


@dataclass
class GuardReceipt:
    verdict: Verdict
    attestation: Attestation
    settled: bool
    amount_settled: int = 0


class AgentGuard:
    def __init__(self, engine: PolicyEngine, attestor: EnclaveAttestor,
                 signer: IsolatedSigner, chain: LocalChain | None = None):
        self.engine = engine
        self.attestor = attestor
        self._signer = signer      # private: not exposed via client handle
        self.chain = chain
        self.audit: list[AuditEntry] = []
        self.policy_hash = engine.policy.hash()

    # ---------- internal ----------
    def _append_audit(self, p: Proposal, verdict: Verdict, att: Attestation, settled: bool) -> None:
        entry = AuditEntry(
            seq=len(self.audit),
            prev_hash=self.audit[-1].hash() if self.audit else "GENESIS",
            proposal=json.loads(p.canonical().decode()),
            verdict=verdict_str(verdict),
            attestation_sig=att.signature_hex,
            settled=settled,
        )
        self.audit.append(entry)

    def verify_audit_chain(self) -> bool:
        prev = "GENESIS"
        for e in self.audit:
            if e.prev_hash != prev:
                return False
            prev = e.hash()
        return True

    # ---------- main entry ----------
    def _decide(self, p: Proposal, mandate_chain=None) -> tuple[Verdict, Attestation]:
        verdict = self.engine.evaluate(p, mandate_chain=mandate_chain)
        att = self.attestor.attest(self.policy_hash, p.canonical(),
                                   verdict_str(verdict), verdict.reasons)
        return verdict, att

    def submit(self, p: Proposal, mandate_chain=None, settle: bool = True) -> GuardReceipt:
        verdict, att = self._decide(p, mandate_chain)
        settled = False
        amount_settled = 0
        if verdict.allow and settle and self.chain is not None:
            tx = self._to_tx(p)
            self.chain.submit(tx)
            self.engine.record(p)
            settled = True
            amount_settled = p.amount
        self._append_audit(p, verdict, att, settled)
        return GuardReceipt(verdict=verdict, attestation=att, settled=settled,
                            amount_settled=amount_settled)

    def _to_tx(self, p: Proposal) -> Tx:
        if p.kind == "transfer":
            return Tx(kind=TxKind.TRANSFER, sender=self._signer.address, to=p.to,
                      amount=p.amount, asset=p.asset,
                      private=bool(p.meta.get("private")))
        return Tx(kind=TxKind.SWAP, sender=self._signer.address, amount_in=p.amount,
                  token_in=p.token_in, token_out=p.token_out, min_out=p.min_out,
                  private=bool(p.meta.get("private")))

    def sign_for_x402(self, digest: bytes, *, kind: str, req) -> tuple[str, str] | None:
        """x402 client signing callback: the requirements become a proposal and
        must pass policy before any signature exists. Settlement is performed
        by the Facilitator (it owns settlement), never duplicated here."""
        p = Proposal(kind="transfer", amount=req.amount, asset=req.asset,
                     to=req.pay_to, purpose=f"x402:{req.resource}",
                     meta={"agent": "x402-client", "nonce": req.nonce})
        verdict, att = self._decide(p)
        if not verdict.allow:
            self._append_audit(p, verdict, att, settled=False)
            return None
        self.engine.record(p)  # settlement happens at the Facilitator
        self._append_audit(p, verdict, att, settled=True)
        return self._signer.sign(digest)


def verdict_str(v: Verdict) -> str:
    return "ALLOW" if v.allow else "DENY"


class GuardClient:
    """The handle agents receive. Submit-only; no signer, no policy mutation."""

    def __init__(self, guard: AgentGuard, agent_address: str):
        self._guard = guard
        self.agent_address = agent_address

    def submit(self, p: Proposal, mandate_chain=None) -> GuardReceipt:
        p.meta.setdefault("agent", self.agent_address)
        return self._guard.submit(p, mandate_chain=mandate_chain)

    def __getattr__(self, name):
        # Defense in depth: agents poking at internals get a clear error.
        raise AttributeError(f"GuardClient has no attribute {name!r} (submit-only)")
