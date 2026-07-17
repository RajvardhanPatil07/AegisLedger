"""Internal chain boundary with deterministic LocalChain and authenticated JSON-RPC adapters."""
from __future__ import annotations

import ipaddress
import itertools
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx
from eth_hash.auto import keccak

from agentwallet.chain.ledger import LocalChain, Receipt, Tx


class RpcConfigurationError(ValueError):
    pass


def keccak_transaction_hash(raw_transaction: str) -> str:
    if not raw_transaction.startswith("0x"):
        raise ValueError("raw transaction must be 0x-prefixed")
    try:
        payload = bytes.fromhex(raw_transaction[2:])
    except ValueError as exc:
        raise ValueError("raw transaction must contain hexadecimal bytes") from exc
    if not payload:
        raise ValueError("raw transaction cannot be empty")
    return "0x" + keccak(payload).hex()


@dataclass(frozen=True)
class ChainSubmission:
    chain_id: int
    transaction_hash: str
    raw_transaction: str | None = None
    local_transaction: Tx | None = None


@dataclass(frozen=True)
class EvmReceipt:
    transaction_hash: str
    block_hash: str
    block_number: int
    success: bool
    confirmations: int


@runtime_checkable
class ChainBackend(Protocol):
    @property
    def chain_id(self) -> int: ...

    def submit(self, submission: ChainSubmission) -> str: ...

    def receipt(self, transaction_hash: str): ...


class LocalChainBackend:
    def __init__(self, chain: LocalChain) -> None:
        self._chain = chain
        self._receipts: dict[str, Receipt] = {}

    @property
    def chain_id(self) -> int:
        return self._chain.chain_id

    def submit(self, submission: ChainSubmission) -> str:
        if submission.chain_id != self.chain_id:
            raise ValueError("submission targets the wrong chain")
        transaction = submission.local_transaction
        if transaction is None:
            raise ValueError("LocalChain backend requires a local transaction")
        if transaction.hash() != submission.transaction_hash:
            raise ValueError("local transaction hash does not match submission")
        self._chain.submit(transaction)
        return transaction.hash()

    def mine(self) -> tuple[Receipt, ...]:
        receipts = tuple(self._chain.mine_block())
        for receipt in receipts:
            self._receipts[receipt.tx.hash()] = receipt
        return receipts

    def receipt(self, transaction_hash: str) -> Receipt | None:
        return self._receipts.get(transaction_hash)


RpcCallable = Callable[[str, list], object]


class JsonRpcChainBackend:
    def __init__(
        self,
        rpc_url: str,
        *,
        expected_chain_id: int,
        authorization_header: str | None = None,
        rpc: RpcCallable | None = None,
        timeout_seconds: float = 10.0,
        finality_confirmations: int = 2,
    ) -> None:
        self._validate_url(rpc_url)
        if expected_chain_id <= 0:
            raise RpcConfigurationError("expected chain ID must be positive")
        if finality_confirmations < 1:
            raise RpcConfigurationError("finality confirmations must be positive")
        self._rpc_url = rpc_url
        self._chain_id = expected_chain_id
        self._finality_confirmations = finality_confirmations
        self._network_verified = False
        self._counter = itertools.count(1)
        self._client = None
        if rpc is None:
            headers = {"Authorization": authorization_header} if authorization_header else {}
            self._client = httpx.Client(
                headers=headers,
                timeout=httpx.Timeout(timeout_seconds),
                follow_redirects=False,
            )
            self._rpc = self._http_rpc
        else:
            self._rpc = rpc

    @staticmethod
    def _validate_url(raw_url: str) -> None:
        parsed = urlparse(raw_url)
        if parsed.username or parsed.password:
            raise RpcConfigurationError("RPC credentials must use an authorization header")
        if not parsed.hostname:
            raise RpcConfigurationError("RPC URL must include a host")
        local = parsed.hostname == "localhost"
        try:
            local = local or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            pass
        if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
            raise RpcConfigurationError("remote RPC endpoints must use HTTPS")

    @property
    def chain_id(self) -> int:
        return self._chain_id

    def _http_rpc(self, method: str, params: list) -> object:
        assert self._client is not None
        response = self._client.post(
            self._rpc_url,
            json={"jsonrpc": "2.0", "id": next(self._counter), "method": method, "params": params},
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
            raise RuntimeError("RPC returned a malformed response")
        if body.get("error") is not None:
            raise RuntimeError("RPC request failed")
        if "result" not in body:
            raise RuntimeError("RPC response omitted result")
        return body["result"]

    def _verify_network(self) -> None:
        if self._network_verified:
            return
        result = self._rpc("eth_chainId", [])
        if not isinstance(result, str):
            raise RuntimeError("RPC chain ID response is malformed")
        try:
            actual_chain_id = int(result, 16)
        except ValueError as exc:
            raise RuntimeError("RPC chain ID response is malformed") from exc
        if actual_chain_id != self.chain_id:
            raise RuntimeError(
                f"RPC is connected to wrong chain {actual_chain_id}; expected {self.chain_id}"
            )
        self._network_verified = True

    def submit(self, submission: ChainSubmission) -> str:
        if submission.chain_id != self.chain_id:
            raise ValueError("submission targets the wrong chain")
        if submission.raw_transaction is None:
            raise ValueError("EVM backend requires an encoded signed transaction")
        self._verify_network()
        computed_hash = keccak_transaction_hash(submission.raw_transaction)
        if computed_hash.lower() != submission.transaction_hash.lower():
            raise ValueError("signed raw transaction hash does not match submission")
        result = self._rpc("eth_sendRawTransaction", [submission.raw_transaction])
        if not isinstance(result, str) or result.lower() != computed_hash.lower():
            raise RuntimeError("RPC returned an unexpected transaction hash")
        return result.lower()

    def receipt(self, transaction_hash: str) -> EvmReceipt | None:
        self._verify_network()
        result = self._rpc("eth_getTransactionReceipt", [transaction_hash])
        if result is None:
            return None
        if not isinstance(result, dict):
            raise RuntimeError("RPC receipt response is malformed")
        try:
            block_number = int(result["blockNumber"], 16)
            status = int(result["status"], 16)
            latest = self._rpc("eth_blockNumber", [])
            latest_number = int(latest, 16)
            confirmations = max(latest_number - block_number + 1, 0)
            return EvmReceipt(
                transaction_hash=result["transactionHash"].lower(),
                block_hash=result["blockHash"].lower(),
                block_number=block_number,
                success=status == 1,
                confirmations=confirmations,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("RPC receipt response is malformed") from exc

    def is_final(self, receipt: EvmReceipt) -> bool:
        return receipt.confirmations >= self._finality_confirmations


class PrivateRelayBackend(JsonRpcChainBackend):
    """Authenticated relay adapter; still verifies network and raw transaction digest."""

    def submit(self, submission: ChainSubmission) -> str:
        if submission.chain_id != self.chain_id or submission.raw_transaction is None:
            raise ValueError("relay submission is incomplete or targets the wrong chain")
        self._verify_network()
        computed_hash = keccak_transaction_hash(submission.raw_transaction)
        if computed_hash.lower() != submission.transaction_hash.lower():
            raise ValueError("signed raw transaction hash does not match submission")
        result = self._rpc(
            "eth_sendPrivateTransaction",
            [{"tx": submission.raw_transaction, "maxBlockNumber": None}],
        )
        if not isinstance(result, str) or result.lower() != computed_hash.lower():
            raise RuntimeError("relay returned an unexpected transaction hash")
        return result.lower()

