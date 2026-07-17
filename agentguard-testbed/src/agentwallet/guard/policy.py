"""Declarative spending-policy language (YAML) with fail-closed parsing.

Schema (all amounts integer micro-USDC):

    name: strict
    per_tx_cap: 500000000            # max per single transaction
    window_caps:                     # cumulative caps over rolling windows
      - {window_s: 3600, cap: 1000000000}
      - {window_s: 86400, cap: 2000000000}
    velocity: {max_tx_per_window: 20, window_s: 3600}
    allowed_assets: [TUSDC, DRB]
    allowlist_recipients: ["0xabc..."]     # empty list = allow all not blocked
    blocklist_recipients: ["0xbad..."]
    require_mandate_above: 100000000       # AP2 mandate required above this amount
    risk:
      dynamic_tightening: true
      pool_move_threshold_bps: 100         # tighten when observed pool moved >1%
      max_slippage_bps: 50                 # cap on swap slippage tolerance
    kill_switch: false

Unknown keys, negative amounts, or malformed values raise PolicyError at load
time (fail-closed: a broken policy never silently becomes permissive).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

import yaml


class PolicyError(ValueError):
    pass


@dataclass
class WindowCap:
    window_s: int
    cap: int


@dataclass
class RiskPolicy:
    dynamic_tightening: bool = False
    pool_move_threshold_bps: int = 100
    max_slippage_bps: int = 100


@dataclass
class Policy:
    name: str
    per_tx_cap: int
    window_caps: list[WindowCap]
    max_tx_per_window: int
    velocity_window_s: int
    allowed_assets: list[str]
    allowlist_recipients: list[str]
    blocklist_recipients: list[str]
    require_mandate_above: int
    risk: RiskPolicy
    kill_switch: bool = False
    raw: dict = field(default_factory=dict)

    def hash(self) -> str:
        return hashlib.sha256(
            json.dumps(self.raw, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


_ALLOWED_KEYS = {
    "name", "per_tx_cap", "window_caps", "velocity", "allowed_assets",
    "allowlist_recipients", "blocklist_recipients", "require_mandate_above",
    "risk", "kill_switch",
}


def _need_int(v, what: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise PolicyError(f"{what} must be an integer, got {type(v).__name__}")
    if v < 0:
        raise PolicyError(f"{what} must be >= 0")
    return v


def _need_positive_int(v, what: str) -> int:
    value = _need_int(v, what)
    if value == 0:
        raise PolicyError(f"{what} must be > 0")
    return value


def _need_bool(v, what: str) -> bool:
    if not isinstance(v, bool):
        raise PolicyError(f"{what} must be a boolean, got {type(v).__name__}")
    return v


def _reject_unknown(data: dict, allowed: set[str], what: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"unknown {what} keys: {sorted(unknown)}")


def _need_str_list(v, what: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise PolicyError(f"{what} must be a list of strings")
    return v


def load_policy(text: str) -> Policy:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")

    unknown = set(data) - _ALLOWED_KEYS
    if unknown:
        raise PolicyError(f"unknown policy keys: {sorted(unknown)}")

    name = data.get("name", "unnamed")
    if not isinstance(name, str):
        raise PolicyError("name must be a string")

    per_tx_cap = _need_int(data.get("per_tx_cap", 0), "per_tx_cap")

    window_caps: list[WindowCap] = []
    for i, wc in enumerate(data.get("window_caps", []) or []):
        if not isinstance(wc, dict):
            raise PolicyError(f"window_caps[{i}] must be a mapping")
        _reject_unknown(wc, {"window_s", "cap"}, f"window_caps[{i}]")
        window_caps.append(WindowCap(
            window_s=_need_positive_int(
                wc.get("window_s", 0), f"window_caps[{i}].window_s"
            ),
            cap=_need_int(wc.get("cap", 0), f"window_caps[{i}].cap"),
        ))

    vel = data.get("velocity", {}) or {}
    if not isinstance(vel, dict):
        raise PolicyError("velocity must be a mapping")
    _reject_unknown(vel, {"max_tx_per_window", "window_s"}, "velocity")
    max_tx = _need_int(vel.get("max_tx_per_window", 0), "velocity.max_tx_per_window")
    vel_win = _need_positive_int(vel.get("window_s", 3600), "velocity.window_s")

    risk_d = data.get("risk", {}) or {}
    if not isinstance(risk_d, dict):
        raise PolicyError("risk must be a mapping")
    _reject_unknown(
        risk_d,
        {"dynamic_tightening", "pool_move_threshold_bps", "max_slippage_bps"},
        "risk",
    )
    risk = RiskPolicy(
        dynamic_tightening=_need_bool(
            risk_d.get("dynamic_tightening", False), "risk.dynamic_tightening"
        ),
        pool_move_threshold_bps=_need_int(risk_d.get("pool_move_threshold_bps", 100),
                                          "risk.pool_move_threshold_bps"),
        max_slippage_bps=_need_int(risk_d.get("max_slippage_bps", 100),
                                   "risk.max_slippage_bps"),
    )

    return Policy(
        name=name,
        per_tx_cap=per_tx_cap,
        window_caps=window_caps,
        max_tx_per_window=max_tx,
        velocity_window_s=vel_win,
        allowed_assets=_need_str_list(data.get("allowed_assets", ["TUSDC"]), "allowed_assets"),
        allowlist_recipients=_need_str_list(data.get("allowlist_recipients", []),
                                            "allowlist_recipients"),
        blocklist_recipients=_need_str_list(data.get("blocklist_recipients", []),
                                            "blocklist_recipients"),
        require_mandate_above=_need_int(data.get("require_mandate_above", 2**63 - 1),
                                        "require_mandate_above"),
        risk=risk,
        kill_switch=_need_bool(data.get("kill_switch", False), "kill_switch"),
        raw=data,
    )


UNRESTRICTED = """name: unrestricted
per_tx_cap: 0
window_caps: []
velocity: {max_tx_per_window: 0, window_s: 3600}
allowed_assets: [TUSDC, DRB]
allowlist_recipients: []
blocklist_recipients: []
require_mandate_above: 9223372036854775807
risk: {dynamic_tightening: false, pool_move_threshold_bps: 100000, max_slippage_bps: 100000}
kill_switch: false
"""
