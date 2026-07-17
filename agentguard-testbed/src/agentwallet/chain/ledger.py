"""In-process deterministic chain: ERC-20-like token, constant-product AMM,
public mempool, and block sealing.

This is a high-fidelity *simulated* ledger: balances, irreversible settlement,
mempool observability (the precondition for MEV), and AMM price impact are all
modeled with the same arithmetic as their on-chain counterparts. The ChainBackend
interface allows a real EVM backend to be substituted without touching the
experiment code.

All money amounts are integers in micro-USDC (6 decimals). No floats anywhere.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import verify_with_address

if TYPE_CHECKING:
    from .crypto import KeyPair

MICRO = 1_000_000  # 1 USDC = 1_000_000 micro-USDC


class TxKind(Enum):
    TRANSFER = "transfer"
    SWAP = "swap"


@dataclass
class Tx:
    kind: TxKind
    sender: str
    # transfer fields
    to: str | None = None
    amount: int = 0
    asset: str = "TUSDC"
    # swap fields
    amount_in: int = 0
    token_in: str = "TUSDC"
    token_out: str = "DRB"
    min_out: int = 0  # slippage protection: minimum acceptable output
    # meta
    private: bool = False  # private txs are invisible to mempool watchers
    submitted_at: int = 0  # logical clock tick
    nonce: int = 0
    chain_id: int = 0
    deadline: int = 0
    decision_hash: str = ""
    public_key_hex: str = ""
    signature_hex: str = ""

    def canonical(self) -> bytes:
        """Canonical authorization payload. Runtime and signature fields are excluded."""
        payload = {
            "amount": self.amount,
            "amount_in": self.amount_in,
            "asset": self.asset,
            "chain_id": self.chain_id,
            "deadline": self.deadline,
            "decision_hash": self.decision_hash,
            "kind": self.kind.value,
            "min_out": self.min_out,
            "nonce": self.nonce,
            "private": self.private,
            "sender": self.sender,
            "to": self.to,
            "token_in": self.token_in,
            "token_out": self.token_out,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> bytes:
        return hashlib.sha256(self.canonical()).digest()

    def hash(self) -> str:
        return self.digest().hex()

    def sign(self, keys: KeyPair) -> Tx:
        if keys.address.lower() != self.sender.lower():
            raise RuleViolation("signing key does not control transaction sender")
        self.public_key_hex = keys.public_key_bytes().hex()
        self.signature_hex = keys.sign(self.digest()).hex()
        return self


@dataclass
class Receipt:
    tx: Tx
    success: bool
    amount_out: int = 0
    error: str = ""


class InsufficientFunds(Exception):
    pass


class RuleViolation(Exception):
    """Raised when a contract-side (smart wallet) rule rejects a transfer."""

    pass


class TestToken:
    """ERC-20-like ledger with transferable balances."""

    def __init__(self, symbol: str):
        self.symbol = symbol
        self.balances: dict[str, int] = {}

    def mint(self, addr: str, amount: int) -> None:
        self.balances[addr] = self.balances.get(addr, 0) + amount

    def balance(self, addr: str) -> int:
        return self.balances.get(addr, 0)

    def transfer(self, frm: str, to: str, amount: int) -> None:
        if amount <= 0:
            raise RuleViolation("non-positive transfer")
        if self.balance(frm) < amount:
            raise InsufficientFunds(f"{frm} has {self.balance(frm)} < {amount}")
        self.balances[frm] -= amount
        self.balances[to] = self.balances.get(to, 0) + amount


class ConstantProductAMM:
    """Uniswap-V2-style pool for the TUSDC/DRB pair. x*y = k, 0.3% fee."""

    FEE_BPS = 30  # 0.30%

    def __init__(self, reserve_a: int, reserve_b: int):
        self.a = reserve_a  # TUSDC
        self.b = reserve_b  # DRB
        assert self.a > 0 and self.b > 0

    def price_a_per_b(self) -> float:
        return self.a / self.b

    def quote(self, token_in: str, amount_in: int) -> int:
        rin, rout = (self.a, self.b) if token_in == "TUSDC" else (self.b, self.a)
        eff = amount_in * (10_000 - self.FEE_BPS)
        return (eff * rout) // (rin * 10_000 + eff)

    def swap(self, token_in: str, amount_in: int, min_out: int = 0) -> int:
        out = self.quote(token_in, amount_in)
        if out < min_out:
            raise RuleViolation(f"slippage: out {out} < min_out {min_out}")
        if token_in == "TUSDC":
            self.a += amount_in
            self.b -= out
        else:
            self.b += amount_in
            self.a -= out
        return out


class LocalChain:
    """Blocks, a public mempool, tokens, one AMM, and contract-wallet hooks.

    Contract wallets register a `rule_hook(tx) -> None` that runs *at settlement
    time* inside the block executor; a violation aborts the transfer. This models
    on-chain enforcement that no host compromise can bypass.
    """

    def __init__(
        self, amm_a: int = 1_000_000 * MICRO, amm_b: int = 500_000 * MICRO, chain_id: int = 31337
    ):
        self.tokens: dict[str, TestToken] = {"TUSDC": TestToken("TUSDC"), "DRB": TestToken("DRB")}
        self.amm = ConstantProductAMM(amm_a, amm_b)
        # Fund the pool account to match the AMM's reserve accounting.
        self.tokens["TUSDC"].mint("amm:pool", amm_a)
        self.tokens["DRB"].mint("amm:pool", amm_b)
        self.mempool: list[Tx] = []
        self.blocks: list[list[Receipt]] = []
        self.clock = 0
        self.chain_id = chain_id
        self._next_nonces: dict[str, int] = {}
        self.rule_hooks: dict[str, Callable[[Tx], None]] = {}  # addr -> hook
        self.events: list[str] = []

    # ---------- funds ----------
    def mint(self, asset: str, addr: str, amount: int) -> None:
        self.tokens[asset].mint(addr, amount)

    def balance(self, asset: str, addr: str) -> int:
        return self.tokens[asset].balance(addr)

    # ---------- mempool ----------
    def next_nonce(self, address: str) -> int:
        return self._next_nonces.get(address.lower(), 0)

    def _verify_authorization(self, tx: Tx) -> None:
        if not tx.public_key_hex or not tx.signature_hex:
            raise RuleViolation("transaction signature required")
        if tx.chain_id != self.chain_id:
            raise RuleViolation(f"wrong chain: transaction {tx.chain_id}, backend {self.chain_id}")
        if tx.deadline < self.clock:
            raise RuleViolation("transaction expired")
        expected = self.next_nonce(tx.sender)
        if tx.nonce != expected:
            raise RuleViolation(f"invalid nonce: expected {expected}, received {tx.nonce}")
        if not tx.decision_hash:
            raise RuleViolation("transaction is not bound to a decision")
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx.public_key_hex))
            sig = bytes.fromhex(tx.signature_hex)
        except (TypeError, ValueError) as exc:
            raise RuleViolation("malformed transaction signature") from exc
        if not verify_with_address(tx.sender, tx.digest(), sig, pub):
            raise RuleViolation("invalid transaction signature")

    def submit(self, tx: Tx) -> None:
        self._verify_authorization(tx)
        tx.submitted_at = self.clock
        self.mempool.append(tx)
        key = tx.sender.lower()
        self._next_nonces[key] = self.next_nonce(key) + 1

    def visible_mempool(self) -> list[Tx]:
        """What a public searcher can see. Private txs are hidden."""
        return [t for t in self.mempool if not t.private]

    # ---------- execution ----------
    def mine_block(self) -> list[Receipt]:
        receipts: list[Receipt] = []
        pending, self.mempool = self.mempool, []
        for tx in pending:
            receipts.append(self._execute(tx))
        self.blocks.append(receipts)
        self.clock += 1
        return receipts

    def _execute(self, tx: Tx) -> Receipt:
        try:
            hook = self.rule_hooks.get(tx.sender)
            if hook is not None:
                hook(tx)  # contract-side rule enforcement (smart wallet)
            if tx.kind is TxKind.TRANSFER:
                self.tokens[tx.asset].transfer(tx.sender, tx.to, tx.amount)
                return Receipt(tx=tx, success=True)
            # swap
            tok_in, tok_out = self.tokens[tx.token_in], self.tokens[tx.token_out]
            if tok_in.balance(tx.sender) < tx.amount_in:
                raise InsufficientFunds("swap input exceeds balance")
            out = self.amm.swap(tx.token_in, tx.amount_in, tx.min_out)
            tok_in.transfer(tx.sender, "amm:pool", tx.amount_in)
            tok_out.transfer("amm:pool", tx.sender, out)
            return Receipt(tx=tx, success=True, amount_out=out)
        except (InsufficientFunds, RuleViolation) as e:
            self.events.append(f"reverted: {e}")
            return Receipt(tx=tx, success=False, error=str(e))

    # ---------- contract wallet registration ----------
    def register_rule_hook(self, addr: str, hook: Callable[[Tx], None]) -> None:
        self.rule_hooks[addr] = hook

    def snapshot_reserves(self) -> tuple[int, int]:
        return self.amm.a, self.amm.b
