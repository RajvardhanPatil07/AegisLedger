import pytest

from aegisledger.rate_limit import MemoryRateLimiter


def test_memory_rate_limiter_denies_after_window_capacity():
    limiter = MemoryRateLimiter()

    assert limiter.consume("principal", limit=2, window_seconds=60)
    assert limiter.consume("principal", limit=2, window_seconds=60)
    assert not limiter.consume("principal", limit=2, window_seconds=60)
    assert limiter.consume("different-principal", limit=2, window_seconds=60)


def test_rate_limiter_rejects_invalid_configuration():
    with pytest.raises(ValueError, match="positive"):
        MemoryRateLimiter().consume("principal", limit=0, window_seconds=60)
