from aegisledger.api import ServiceContainer
from aegisledger.decisions import DecisionIssuer
from aegisledger.policies import PolicyRegistry
from aegisledger.policy import PolicyV1
from aegisledger.state import MemoryStateStore

WALLET = "0x" + "12" * 20
RECIPIENT = "0x" + "34" * 20


def active_services() -> ServiceContainer:
    policy = PolicyV1.model_validate(
        {
            "schema_version": "aegisledger.policy.v1",
            "name": "runtime-test-policy",
            "default_action": "deny",
            "enabled_wallets": [WALLET],
            "enabled_principals": ["viewer"],
            "enabled_chains": [31337],
            "enabled_assets": ["TUSDC"],
            "allowed_recipients": [RECIPIENT],
            "contract_rules": [],
            "per_transaction_cap": 100,
            "rolling_caps": [{"window_seconds": 3600, "amount": 100}],
            "maximum_transactions_per_hour": 10,
            "mandate_required_above": 100,
            "risk": {
                "maximum_slippage_bps": 50,
                "maximum_quote_age_seconds": 30,
                "deny_on_missing_quote": True,
            },
            "emergency_stop": False,
        }
    )
    policies = PolicyRegistry()
    version = policies.create(policy, created_by="author")
    policies.approve(version.version_id, "admin-a")
    policies.approve(version.version_id, "admin-b")
    policies.activate(version.version_id, activated_by="admin-a")
    return ServiceContainer(
        policies=policies,
        state=MemoryStateStore(),
        decisions=DecisionIssuer.from_seed("runtime-test"),
    )
