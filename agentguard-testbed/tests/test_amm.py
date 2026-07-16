"""AMM arithmetic: constant-product invariant, price impact, min_out revert."""
import pytest

from agentwallet.chain.ledger import ConstantProductAMM, RuleViolation, MICRO


def test_quote_positive_and_increasing():
    amm = ConstantProductAMM(50_000 * MICRO, 25_000 * MICRO)
    q1 = amm.quote("TUSDC", 100 * MICRO)
    q2 = amm.quote("TUSDC", 200 * MICRO)
    assert q1 > 0 and q2 > q1


def test_price_impact_grows_with_size():
    amm = ConstantProductAMM(50_000 * MICRO, 25_000 * MICRO)
    spot = amm.b / amm.a
    small = amm.quote("TUSDC", 100 * MICRO) / (100 * MICRO)
    big = amm.quote("TUSDC", 5_000 * MICRO) / (5_000 * MICRO)
    assert big < small < spot  # worse effective price for bigger trades


def test_constant_product_direction():
    amm = ConstantProductAMM(50_000 * MICRO, 25_000 * MICRO)
    k0 = amm.a * amm.b
    amm.swap("TUSDC", 1_000 * MICRO)
    assert amm.a * amm.b >= k0  # fee makes k non-decreasing


def test_min_out_revert():
    amm = ConstantProductAMM(50_000 * MICRO, 25_000 * MICRO)
    quote = amm.quote("TUSDC", 1_000 * MICRO)
    with pytest.raises(RuleViolation):
        amm.swap("TUSDC", 1_000 * MICRO, min_out=quote + 1)


def test_round_trip_loses_fees():
    amm = ConstantProductAMM(50_000 * MICRO, 25_000 * MICRO)
    got = amm.swap("TUSDC", 1_000 * MICRO)
    back = amm.swap("DRB", got)
    assert back < 1_000 * MICRO  # round trip costs fees+impact
