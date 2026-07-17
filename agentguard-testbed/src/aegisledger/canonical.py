"""Canonical identifiers and JSON used by signed authorization artifacts."""
from __future__ import annotations

import json
import secrets
import time
import uuid
from typing import Any

try:
    import rfc8785
except ImportError:  # pragma: no cover - only used before dependencies are installed
    rfc8785 = None


class CanonicalizationError(ValueError):
    pass


def uuid7(now_ms: int | None = None) -> uuid.UUID:
    """Generate a time-sortable UUIDv7 as specified by RFC 9562."""
    timestamp = int(time.time_ns() // 1_000_000 if now_ms is None else now_ms)
    if not 0 <= timestamp < 1 << 48:
        raise ValueError("UUIDv7 timestamp is outside the 48-bit range")
    random_bits = secrets.randbits(74)
    value = timestamp << 80
    value |= 0x7 << 76
    value |= ((random_bits >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= random_bits & ((1 << 62) - 1)
    return uuid.UUID(int=value)


def _assert_supported(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"floating-point values are forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_supported(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise CanonicalizationError(f"object keys must be strings at {path}")
        for key, item in value.items():
            _assert_supported(item, f"{path}.{key}")
        return
    raise CanonicalizationError(f"unsupported canonical JSON type at {path}: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return RFC 8785 JSON bytes; signed domains deliberately forbid floats."""
    _assert_supported(value)
    if rfc8785 is not None:
        return rfc8785.dumps(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

