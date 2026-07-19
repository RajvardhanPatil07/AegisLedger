from dataclasses import replace

import pytest

from aegisledger.chain import (
    ChainSubmission,
    JsonRpcChainBackend,
    LocalChainBackend,
    RpcConfigurationError,
    keccak_transaction_hash,
)
from agentwallet.chain.crypto import KeyPair
from agentwallet.chain.ledger import LocalChain, Tx, TxKind


def signed_local_transaction(chain: LocalChain, keys: KeyPair) -> Tx:
    return Tx(
        kind=TxKind.TRANSFER,
        sender=keys.address,
        to="0xrecipient",
        amount=10,
        chain_id=chain.chain_id,
        nonce=chain.next_nonce(keys.address),
        deadline=chain.clock + 10,
        decision_hash="backend-test-decision",
    ).sign(keys)


def test_local_backend_accepts_only_matching_signed_local_transaction():
    chain = LocalChain(chain_id=31337)
    keys = KeyPair.from_seed("backend-owner")
    chain.mint("TUSDC", keys.address, 100)
    backend = LocalChainBackend(chain)
    tx = signed_local_transaction(chain, keys)
    tx_hash = backend.submit(
        ChainSubmission(chain_id=31337, transaction_hash=tx.hash(), local_transaction=tx)
    )
    assert tx_hash == tx.hash()
    backend.mine()
    assert backend.receipt(tx_hash).success


def test_json_rpc_backend_rejects_insecure_remote_endpoint():
    with pytest.raises(RpcConfigurationError, match="HTTPS"):
        JsonRpcChainBackend("http://rpc.example.test", expected_chain_id=31337)


def test_json_rpc_backend_verifies_chain_and_exact_raw_transaction_hash():
    calls = []
    raw_transaction = "0x02c0"
    expected_hash = keccak_transaction_hash(raw_transaction)

    def rpc(method, params):
        calls.append((method, params))
        if method == "eth_chainId":
            return "0x7a69"
        if method == "eth_sendRawTransaction":
            return expected_hash
        raise AssertionError(method)

    backend = JsonRpcChainBackend(
        "http://127.0.0.1:8545",
        expected_chain_id=31337,
        rpc=rpc,
    )
    submission = ChainSubmission(
        chain_id=31337,
        transaction_hash=expected_hash,
        raw_transaction=raw_transaction,
    )
    assert backend.submit(submission) == expected_hash
    assert calls == [
        ("eth_chainId", []),
        ("eth_sendRawTransaction", [raw_transaction]),
    ]

    with pytest.raises(ValueError, match="hash"):
        backend.submit(replace(submission, transaction_hash="0x" + "00" * 32))


def test_json_rpc_backend_fails_closed_on_wrong_network():
    backend = JsonRpcChainBackend(
        "http://localhost:8545",
        expected_chain_id=31337,
        rpc=lambda method, _params: "0x1" if method == "eth_chainId" else None,
    )
    with pytest.raises(RuntimeError, match="wrong chain"):
        backend.submit(
            ChainSubmission(
                chain_id=31337,
                transaction_hash=keccak_transaction_hash("0x02c0"),
                raw_transaction="0x02c0",
            )
        )
