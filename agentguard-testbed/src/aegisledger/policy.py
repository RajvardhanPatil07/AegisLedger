"""Fail-closed policy contracts used for approval, hashing, and simulation."""
from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from .canonical import canonical_json
from .contracts import Address, AssetId, Selector, StrictModel


class RollingCapV1(StrictModel):
    window_seconds: Annotated[int, Field(gt=0)]
    amount: Annotated[int, Field(ge=0)]


class RiskConstraintsV1(StrictModel):
    maximum_slippage_bps: Annotated[int, Field(ge=0, le=10_000)]
    maximum_quote_age_seconds: Annotated[int, Field(gt=0)]
    deny_on_missing_quote: bool


class ContractRuleV1(StrictModel):
    contract: Address
    selectors: tuple[Selector, ...]

    @field_validator("selectors", mode="before")
    @classmethod
    def accept_json_array(cls, values):
        if not isinstance(values, (list, tuple)):
            raise TypeError("selectors must be an array")
        return tuple(values)

    @field_validator("contract")
    @classmethod
    def normalize_contract(cls, value: str) -> str:
        return value.lower()


class PolicyV1(StrictModel):
    schema_version: Literal["aegisledger.policy.v1"]
    name: Annotated[str, StringConstraints(min_length=3, max_length=96)]
    default_action: Literal["deny"]
    enabled_wallets: tuple[Address, ...]
    enabled_principals: tuple[Annotated[str, StringConstraints(min_length=1, max_length=128)], ...]
    enabled_chains: tuple[Annotated[int, Field(gt=0)], ...]
    enabled_assets: tuple[AssetId, ...]
    allowed_recipients: tuple[Address, ...]
    contract_rules: tuple[ContractRuleV1, ...]
    per_transaction_cap: Annotated[int, Field(ge=0)]
    rolling_caps: tuple[RollingCapV1, ...]
    maximum_transactions_per_hour: Annotated[int, Field(ge=0)]
    mandate_required_above: Annotated[int, Field(ge=0)]
    risk: RiskConstraintsV1
    emergency_stop: bool

    @field_validator(
        "enabled_wallets",
        "enabled_principals",
        "enabled_chains",
        "enabled_assets",
        "allowed_recipients",
        "contract_rules",
        "rolling_caps",
        mode="before",
    )
    @classmethod
    def accept_json_arrays(cls, values):
        if not isinstance(values, (list, tuple)):
            raise TypeError("policy collection fields must be arrays")
        return tuple(values)

    @field_validator("enabled_wallets", "allowed_recipients")
    @classmethod
    def normalize_addresses(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({value.lower() for value in values}))

    @field_validator("enabled_principals", "enabled_assets", "enabled_chains")
    @classmethod
    def normalize_values(cls, values: tuple) -> tuple:
        return tuple(sorted(set(values)))

    @model_validator(mode="after")
    def explicit_constraints_are_coherent(self) -> "PolicyV1":
        windows = [cap.window_seconds for cap in self.rolling_caps]
        if len(windows) != len(set(windows)):
            raise ValueError("rolling cap windows must be unique")
        if self.per_transaction_cap == 0 and not self.emergency_stop:
            raise ValueError("a zero per-transaction cap requires emergency_stop")
        return self

    def normalized(self) -> dict:
        return self.model_dump(mode="json")

    def policy_hash(self) -> str:
        return "0x" + hashlib.sha256(canonical_json(self.normalized())).hexdigest()
