"""Security regressions for signed local-ledger authorization."""

import pytest

from agentwallet.chain.crypto import KeyPair
from agentwallet.chain.ledger import LocalChain, RuleViolation, Tx, TxKind
from agentwallet.guard.engine import Proposal
from agentwallet.testbed import DefenseMode, Testbed


def transfer(keys: KeyPair, chain: LocalChain, *, amount: int = 10) -> Tx:
    return Tx(
        kind=TxKind.TRANSFER,
        sender=keys.address,
        to="0xrecipient",
        amount=amount,
        asset="TUSDC",
        chain_id=chain.chain_id,
        nonce=chain.next_nonce(keys.address),
        deadline=chain.clock + 10,
        decision_hash="external:test-decision",
    ).sign(keys)


def test_unsigned_transaction_is_rejected_before_mempool_entry():
    chain = LocalChain()
    keys = KeyPair.from_seed("unsigned-owner")
    chain.mint("TUSDC", keys.address, 100)
    tx = Tx(kind=TxKind.TRANSFER, sender=keys.address, to="0xrecipient",
            amount=10, asset="TUSDC")

    with pytest.raises(RuleViolation, match="signature"):
        chain.submit(tx)

    assert chain.mempool == []


def test_signed_transaction_settles_once():
    chain = LocalChain()
    keys = KeyPair.from_seed("signed-owner")
    chain.mint("TUSDC", keys.address, 100)
    tx = transfer(keys, chain)

    chain.submit(tx)
    receipt = chain.mine_block()[0]

    assert receipt.success
    assert chain.balance("TUSDC", "0xrecipient") == 10


def test_signed_transaction_cannot_be_replayed():
    chain = LocalChain()
    keys = KeyPair.from_seed("replay-owner")
    chain.mint("TUSDC", keys.address, 100)
    tx = transfer(keys, chain)
    chain.submit(tx)

    with pytest.raises(RuleViolation, match="nonce"):
        chain.submit(tx)


def test_mutating_signed_transaction_invalidates_signature():
    chain = LocalChain()
    keys = KeyPair.from_seed("mutation-owner")
    chain.mint("TUSDC", keys.address, 100)
    tx = transfer(keys, chain)
    tx.amount = 11

    with pytest.raises(RuleViolation, match="signature"):
        chain.submit(tx)


def test_wrong_chain_and_expired_transactions_are_rejected():
    chain = LocalChain(chain_id=31337)
    keys = KeyPair.from_seed("scope-owner")
    chain.mint("TUSDC", keys.address, 100)

    wrong_chain = transfer(keys, chain)
    wrong_chain.chain_id = 1
    wrong_chain.sign(keys)
    with pytest.raises(RuleViolation, match="chain"):
        chain.submit(wrong_chain)

    expired = transfer(keys, chain)
    expired.deadline = chain.clock - 1
    expired.sign(keys)
    with pytest.raises(RuleViolation, match="expired"):
        chain.submit(expired)


def test_agent_capability_exposes_neither_guard_signer_nor_chain():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="capability-boundary")

    assert not hasattr(tb.client, "_guard")
    assert not hasattr(tb.client, "signer")
    assert not hasattr(tb.executor, "chain")


def test_guard_records_spend_only_after_successful_settlement():
    tb = Testbed(mode=DefenseMode.GUARD_STRICT, seed="settlement-truth")
    tb.chain.tokens["TUSDC"].balances[tb.wallet] = 0

    receipt = tb.client.submit(Proposal(
        kind="transfer",
        amount=1_000_000,
        to=tb.vendors["data-api"],
        purpose="will-revert",
    ))
    mined = tb.mine()[0]

    assert receipt.verdict.allow
    assert not receipt.settled
    assert not mined.success
    assert not tb.guard.audit[-1].settled
    assert tb.guard.engine.history == []


def test_wallet_key_material_has_no_export_api():
    keys = KeyPair.from_seed("non-exportable")

    assert not hasattr(keys, "private_bytes_for_backup_only")
