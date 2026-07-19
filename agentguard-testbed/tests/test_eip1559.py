import pytest
from hypothesis import given
from hypothesis import strategies as st

from aegisledger.eip1559 import Eip1559DecodeError, decode_unsigned_eip1559


def rlp_prefix(payload: bytes, short_offset: int, long_offset: int) -> bytes:
    if len(payload) < 56:
        return bytes([short_offset + len(payload)]) + payload
    encoded_length = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([long_offset + len(encoded_length)]) + encoded_length + payload


def rlp(value: bytes | int | list) -> bytes:
    if isinstance(value, list):
        return rlp_prefix(b"".join(rlp(item) for item in value), 0xC0, 0xF7)
    if isinstance(value, int):
        value = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(value) == 1 and value[0] < 0x80:
        return value
    return rlp_prefix(value, 0x80, 0xB7)


def transaction(fields: list) -> str:
    return "0x02" + rlp(fields).hex()


@given(
    chain_id=st.integers(min_value=1, max_value=2**32),
    nonce=st.integers(min_value=0, max_value=2**32),
    priority_fee=st.integers(min_value=0, max_value=10**12),
    fee_delta=st.integers(min_value=1, max_value=10**12),
    gas_limit=st.integers(min_value=21_000, max_value=30_000_000),
    target=st.binary(min_size=20, max_size=20),
    value=st.integers(min_value=0, max_value=2**128),
    calldata=st.binary(max_size=128),
)
def test_canonical_type_two_fields_round_trip(
    chain_id, nonce, priority_fee, fee_delta, gas_limit, target, value, calldata
):
    max_fee = priority_fee + fee_delta
    payload = transaction(
        [chain_id, nonce, priority_fee, max_fee, gas_limit, target, value, calldata, []]
    )

    decoded = decode_unsigned_eip1559(payload)

    assert decoded.chain_id == chain_id
    assert decoded.nonce == nonce
    assert decoded.max_priority_fee_per_gas == priority_fee
    assert decoded.max_fee_per_gas == max_fee
    assert decoded.gas_limit == gas_limit
    assert decoded.to == "0x" + target.hex()
    assert decoded.value == value
    assert decoded.calldata == "0x" + calldata.hex()


def test_noncanonical_integer_and_trailing_bytes_are_rejected():
    fields = [1, b"\x00", 1, 2, 21_000, b"\x12" * 20, 0, b"", []]
    with pytest.raises(Eip1559DecodeError, match="leading zero"):
        decode_unsigned_eip1559(transaction(fields))

    valid = transaction([1, 0, 1, 2, 21_000, b"\x12" * 20, 0, b"", []])
    with pytest.raises(Eip1559DecodeError, match="trailing"):
        decode_unsigned_eip1559(valid + "00")


def test_contract_creation_and_access_lists_are_rejected():
    common = [1, 0, 1, 2, 21_000]
    with pytest.raises(Eip1559DecodeError, match="contract creation"):
        decode_unsigned_eip1559(transaction([*common, b"", 0, b"", []]))

    with pytest.raises(Eip1559DecodeError, match="access lists"):
        decode_unsigned_eip1559(
            transaction([*common, b"\x12" * 20, 0, b"", [[b"\x34" * 20, []]]])
        )


def test_oversized_payload_is_rejected_before_rlp_walk():
    with pytest.raises(Eip1559DecodeError, match="size limit"):
        decode_unsigned_eip1559("0x02" + "80" * (128 * 1024 + 1))
