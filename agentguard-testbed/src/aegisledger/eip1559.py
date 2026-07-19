"""Minimal, fail-closed EIP-1559 codec for the Python reference gate.

The production signer uses Alloy's Rust implementation. This module deliberately
supports only the unsigned type-2 shape accepted by AegisLedger and rejects
non-canonical RLP, contract creation, access lists, and trailing bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_TRANSACTION_BYTES = 128 * 1024
MAX_RLP_DEPTH = 4


class Eip1559DecodeError(ValueError):
    """Raised when an unsigned type-2 transaction is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class UnsignedEip1559:
    chain_id: int
    nonce: int
    max_priority_fee_per_gas: int
    max_fee_per_gas: int
    gas_limit: int
    to: str
    value: int
    calldata: str


RlpValue = bytes | list["RlpValue"]


def _read_length(data: bytes, offset: int, length_size: int) -> tuple[int, int]:
    end = offset + length_size
    if length_size == 0 or end > len(data) or data[offset] == 0:
        raise Eip1559DecodeError("invalid RLP length")
    return int.from_bytes(data[offset:end], "big"), end


def _decode_rlp(data: bytes, offset: int, depth: int = 0) -> tuple[RlpValue, int]:
    if offset >= len(data):
        raise Eip1559DecodeError("truncated RLP item")
    if depth > MAX_RLP_DEPTH:
        raise Eip1559DecodeError("RLP nesting is too deep")
    prefix = data[offset]
    if prefix <= 0x7F:
        return bytes([prefix]), offset + 1
    if prefix <= 0xB7:
        length = prefix - 0x80
        start = offset + 1
        end = start + length
        if end > len(data):
            raise Eip1559DecodeError("truncated RLP string")
        if length == 1 and data[start] < 0x80:
            raise Eip1559DecodeError("non-canonical RLP string")
        return data[start:end], end
    if prefix <= 0xBF:
        length, start = _read_length(data, offset + 1, prefix - 0xB7)
        if length < 56:
            raise Eip1559DecodeError("non-canonical long RLP string")
        end = start + length
        if end > len(data):
            raise Eip1559DecodeError("truncated long RLP string")
        return data[start:end], end

    if prefix <= 0xF7:
        length = prefix - 0xC0
        start = offset + 1
    else:
        length, start = _read_length(data, offset + 1, prefix - 0xF7)
        if length < 56:
            raise Eip1559DecodeError("non-canonical long RLP list")
    end = start + length
    if end > len(data):
        raise Eip1559DecodeError("truncated RLP list")
    items: list[RlpValue] = []
    cursor = start
    while cursor < end:
        item, cursor = _decode_rlp(data, cursor, depth + 1)
        if cursor > end:
            raise Eip1559DecodeError("RLP child exceeds its list")
        items.append(item)
    if cursor != end:
        raise Eip1559DecodeError("invalid RLP list length")
    return items, end


def _integer(value: RlpValue, name: str) -> int:
    if not isinstance(value, bytes):
        raise Eip1559DecodeError(f"{name} must be an RLP byte string")
    if value.startswith(b"\x00"):
        raise Eip1559DecodeError(f"{name} has a non-canonical leading zero")
    return int.from_bytes(value, "big")


def decode_unsigned_eip1559(payload: str) -> UnsignedEip1559:
    """Decode the exact canonical type-2 signing payload used by the signer."""
    if not payload.startswith("0x02") or len(payload) % 2:
        raise Eip1559DecodeError("payload must be an even-length 0x02 hex value")
    try:
        encoded = bytes.fromhex(payload[2:])
    except ValueError as error:
        raise Eip1559DecodeError("payload contains invalid hexadecimal data") from error
    if len(encoded) > MAX_TRANSACTION_BYTES:
        raise Eip1559DecodeError("payload exceeds the transaction size limit")
    transaction, cursor = _decode_rlp(encoded, 1)
    if cursor != len(encoded):
        raise Eip1559DecodeError("payload contains trailing bytes")
    if not isinstance(transaction, list) or len(transaction) != 9:
        raise Eip1559DecodeError("type-2 transaction must contain exactly nine fields")

    chain_id, nonce, priority_fee, max_fee, gas_limit, to, value, calldata, access_list = (
        transaction
    )
    if not isinstance(to, bytes) or len(to) != 20:
        raise Eip1559DecodeError("contract creation and malformed targets are not authorized")
    if not isinstance(calldata, bytes):
        raise Eip1559DecodeError("calldata must be an RLP byte string")
    if not isinstance(access_list, list) or access_list:
        raise Eip1559DecodeError("access lists are not authorized")
    decoded = UnsignedEip1559(
        chain_id=_integer(chain_id, "chain_id"),
        nonce=_integer(nonce, "nonce"),
        max_priority_fee_per_gas=_integer(priority_fee, "max_priority_fee_per_gas"),
        max_fee_per_gas=_integer(max_fee, "max_fee_per_gas"),
        gas_limit=_integer(gas_limit, "gas_limit"),
        to="0x" + to.hex(),
        value=_integer(value, "value"),
        calldata="0x" + calldata.hex(),
    )
    if decoded.chain_id <= 0 or decoded.gas_limit <= 0 or decoded.max_fee_per_gas <= 0:
        raise Eip1559DecodeError("chain, gas limit, and maximum fee must be positive")
    if decoded.max_priority_fee_per_gas > decoded.max_fee_per_gas:
        raise Eip1559DecodeError("priority fee exceeds maximum fee")
    return decoded


def _encode_bytes(value: bytes) -> bytes:
    if len(value) == 1 and value[0] < 0x80:
        return value
    if len(value) < 56:
        return bytes([0x80 + len(value)]) + value
    length = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(length)]) + length + value


def _encode_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("EIP-1559 integers cannot be negative")
    encoded = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    return _encode_bytes(encoded)


def _encode_list(items: list[bytes]) -> bytes:
    payload = b"".join(items)
    if len(payload) < 56:
        return bytes([0xC0 + len(payload)]) + payload
    length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length)]) + length + payload


def encode_unsigned_eip1559(
    *,
    chain_id: int,
    nonce: int,
    max_priority_fee_per_gas: int,
    max_fee_per_gas: int,
    gas_limit: int,
    to: str,
    value: int,
    calldata: str,
) -> str:
    """Encode the constrained canonical unsigned type-2 transaction shape."""
    if not to.startswith("0x") or len(to) != 42:
        raise ValueError("EIP-1559 target must be a 20-byte 0x-prefixed address")
    if not calldata.startswith("0x") or len(calldata) % 2:
        raise ValueError("EIP-1559 calldata must be even-length 0x-prefixed hexadecimal data")
    try:
        target_bytes = bytes.fromhex(to[2:])
        calldata_bytes = bytes.fromhex(calldata[2:])
    except ValueError as error:
        raise ValueError("EIP-1559 target or calldata contains invalid hex") from error
    if chain_id <= 0 or gas_limit <= 0 or max_fee_per_gas <= 0:
        raise ValueError("chain, gas limit, and maximum fee must be positive")
    if max_priority_fee_per_gas > max_fee_per_gas:
        raise ValueError("priority fee exceeds maximum fee")
    encoded = b"\x02" + _encode_list(
        [
            _encode_integer(chain_id),
            _encode_integer(nonce),
            _encode_integer(max_priority_fee_per_gas),
            _encode_integer(max_fee_per_gas),
            _encode_integer(gas_limit),
            _encode_bytes(target_bytes),
            _encode_integer(value),
            _encode_bytes(calldata_bytes),
            _encode_list([]),
        ]
    )
    if len(encoded) > MAX_TRANSACTION_BYTES:
        raise ValueError("encoded EIP-1559 transaction exceeds the size limit")
    return "0x" + encoded.hex()
