"""Unit tests for the policy language and PolicyEngine semantics."""
import pytest

from agentwallet.guard.policy import load_policy, PolicyError
from agentwallet.guard.engine import PolicyEngine, Proposal

BASE = """name: t
per_tx_cap: 100
window_caps:
  - {window_s: 3600, cap: 250}
  - {window_s: 86400, cap: 400}
velocity: {max_tx_per_window: 3, window_s: 3600}
allowed_assets: [TUSDC]
allowlist_recipients: ["0xaaa", "0xbbb"]
blocklist_recipients: ["0xevil"]
require_mandate_above: 100000000
risk: {dynamic_tightening: true, pool_move_threshold_bps: 100, max_slippage_bps: 50}
kill_switch: false
"""


def make_engine(text=BASE, now=1000):
    return PolicyEngine(load_policy(text), now=lambda: now)


def transfer(amount=10, to="0xaaa", asset="TUSDC"):
    return Proposal(kind="transfer", amount=amount, asset=asset, to=to)


class TestParsing:
    def test_unknown_key_rejected(self):
        with pytest.raises(PolicyError):
            load_policy(BASE + "\nbackdoor: true\n")

    def test_negative_cap_rejected(self):
        with pytest.raises(PolicyError):
            load_policy(BASE.replace("per_tx_cap: 100", "per_tx_cap: -1"))

    def test_bool_not_int_rejected(self):
        with pytest.raises(PolicyError):
            load_policy(BASE.replace("per_tx_cap: 100", "per_tx_cap: true"))

    def test_bad_yaml_rejected(self):
        with pytest.raises(PolicyError):
            load_policy("name: [unclosed")

    def test_scalar_policy_rejected(self):
        with pytest.raises(PolicyError):
            load_policy("42")

    @pytest.mark.parametrize("field", ["kill_switch", "dynamic_tightening"])
    def test_boolean_strings_are_not_coerced(self, field):
        if field == "kill_switch":
            text = "name: strict\nper_tx_cap: 100\nkill_switch: 'false'\n"
        else:
            text = (
                "name: strict\nper_tx_cap: 100\n"
                "risk: {dynamic_tightening: 'false', pool_move_threshold_bps: 100, "
                "max_slippage_bps: 100}\n"
            )
        with pytest.raises(PolicyError, match="boolean"):
            load_policy(text)

    @pytest.mark.parametrize(
        "text",
        [
            "name: strict\nper_tx_cap: 100\nrisk: {dynamic_tightening: false, hidden_allow: true}\n",
            "name: strict\nper_tx_cap: 100\nvelocity: {max_tx_per_window: 2, window_s: 60, hidden_allow: true}\n",
            "name: strict\nper_tx_cap: 100\nwindow_caps: [{window_s: 60, cap: 100, hidden_allow: true}]\n",
        ],
    )
    def test_unknown_nested_policy_fields_are_rejected(self, text):
        with pytest.raises(PolicyError, match="unknown"):
            load_policy(text)

    def test_zero_length_cap_window_is_rejected(self):
        with pytest.raises(PolicyError, match="window_s must be > 0"):
            load_policy(
                "name: strict\nper_tx_cap: 100\nwindow_caps: [{window_s: 0, cap: 100}]\n"
            )


class TestCaps:
    def test_under_cap_allowed(self):
        assert make_engine().evaluate(transfer(100)).allow

    def test_over_cap_denied(self):
        v = make_engine().evaluate(transfer(101))
        assert not v.allow and any("per-tx cap" in r for r in v.reasons)

    def test_window_cap_cumulative(self):
        now = [1000]
        e = PolicyEngine(load_policy(BASE), now=lambda: now[0])
        for _ in range(2):
            p = transfer(100)
            assert e.evaluate(p).allow
            e.record(p)
        v = e.evaluate(transfer(100))  # 200 + 100 > 250 hourly
        assert not v.allow and any("window cap" in r for r in v.reasons)

    def test_window_rolls(self):
        now = [1000]
        e = PolicyEngine(load_policy(BASE), now=lambda: now[0])
        for _ in range(2):
            p = transfer(100)
            e.record(p)
        now[0] += 3601  # hourly window expires
        assert e.evaluate(transfer(100)).allow

    def test_velocity(self):
        e = make_engine()
        for _ in range(3):
            p = transfer(10)
            assert e.evaluate(p).allow
            e.record(p)
        assert not e.evaluate(transfer(10)).allow


class TestRecipients:
    def test_blocklist_denied(self):
        assert not make_engine().evaluate(transfer(10, to="0xevil")).allow

    def test_not_on_allowlist_denied(self):
        assert not make_engine().evaluate(transfer(10, to="0xstranger")).allow

    def test_allowlisted_ok(self):
        assert make_engine().evaluate(transfer(10, to="0xbbb")).allow


class TestAssetsAndValidation:
    def test_unlisted_asset_denied(self):
        assert not make_engine().evaluate(transfer(10, asset="SCAM")).allow

    def test_malformed_fails_closed(self):
        assert not make_engine().evaluate(Proposal(kind="transfer", amount=-5, to="0xaaa")).allow
        assert not make_engine().evaluate(Proposal(kind="transfer", amount=10, to="")).allow
        assert not make_engine().evaluate(Proposal(kind="warp", amount=10, to="0xaaa")).allow


class TestRiskControls:
    def test_pool_move_triggers_deny(self):
        e = make_engine()
        e.pool_move_bps = 250
        v = e.evaluate(Proposal(kind="swap", amount=50, min_out=90, quoted_out=100))
        assert not v.allow and any("pool moved" in r for r in v.reasons)

    def test_slippage_tolerance_capped(self):
        e = make_engine()
        v = e.evaluate(Proposal(kind="swap", amount=50, min_out=90, quoted_out=100))
        assert not v.allow and any("slippage" in r for r in v.reasons)

    def test_tight_slippage_calm_pool_allowed(self):
        e = make_engine()
        e.pool_move_bps = 10
        v = e.evaluate(Proposal(kind="swap", amount=50, min_out=995, quoted_out=1000))
        assert v.allow


class TestKillSwitch:
    def test_kill_switch_denies_everything(self):
        e = make_engine(BASE.replace("kill_switch: false", "kill_switch: true"))
        assert not e.evaluate(transfer(1)).allow
