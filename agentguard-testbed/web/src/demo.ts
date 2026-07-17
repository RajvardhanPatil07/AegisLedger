import type {
  AttestationResult,
  AuditEvent,
  ConsoleApi,
  ExperimentRequest,
  ExperimentResult,
  PolicySimulation,
  ProposalStatus,
} from "./types";

export const DEMO_PROPOSAL_ID = "0198f1c1-2b3c-7000-8000-000000000101";
export const DEMO_EXPERIMENT_ID = "0198f1c1-2b3c-7000-8000-000000000202";

export function examplePolicy(): Record<string, unknown> {
  return {
    schema_version: "aegisledger.policy.v1",
    name: "development-research-policy",
    default_action: "deny",
    enabled_wallets: ["0x1212121212121212121212121212121212121212"],
    enabled_principals: ["00000000-0000-4000-8000-000000000101"],
    enabled_chains: [31337],
    enabled_assets: ["TUSDC", "DRB"],
    allowed_recipients: ["0x3434343434343434343434343434343434343434"],
    contract_rules: [],
    per_transaction_cap: 250000000,
    rolling_caps: [
      { window_seconds: 3600, amount: 800000000 },
      { window_seconds: 86400, amount: 1000000000 },
    ],
    maximum_transactions_per_hour: 10,
    mandate_required_above: 100000000,
    risk: {
      maximum_slippage_bps: 50,
      maximum_quote_age_seconds: 30,
      deny_on_missing_quote: true,
    },
    emergency_stop: false,
  };
}

export function exampleProposal(): Record<string, unknown> {
  return {
    schema_version: "aegisledger.proposal.v1",
    principal_id: "00000000-0000-4000-8000-000000000101",
    wallet: "0x1212121212121212121212121212121212121212",
    chain_id: 31337,
    asset: "TUSDC",
    amount: 50000000,
    intent: {
      kind: "transfer",
      recipient: "0x3434343434343434343434343434343434343434",
    },
    deadline: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    idempotency_key: `console-simulation-${Date.now()}`,
  };
}

const completedExperiment: ExperimentResult = {
  experiment_id: DEMO_EXPERIMENT_ID,
  status: "COMPLETED",
  seed: "research-baseline-07",
  configuration_hash: `0x${"7c".repeat(32)}`,
  result_uri: "artifacts/experiments/demo/summary.json",
  error: null,
  summary: {
    raw_run_count: 240,
    false_positive_rate: 0.025,
    availability_cost: 0.025,
    performance: {
      evaluation_duration_ms: 1842.7,
      throughput_runs_per_second: 130.24,
      local_signing_p95_ms: 0.41,
    },
    attack_metrics: [
      { name: "Composed injection", defense: "guarded", success_rate: 0.0 },
      { name: "Tool poisoning", defense: "guarded", success_rate: 0.0 },
      { name: "Inbound permission", defense: "guarded", success_rate: 0.017 },
      { name: "MEV extraction", defense: "guarded", success_rate: 0.025 },
    ],
  },
};

const auditEvents: AuditEvent[] = [
  {
    sequence: 1042,
    event_type: "POLICY_VERSION_ACTIVATED",
    actor: "policy-admin-a",
    occurred_at: "2026-07-17T16:48:05Z",
    payload: { policy_hash: `0x${"a9".repeat(32)}` },
  },
  {
    sequence: 1043,
    event_type: "POLICY_DECISION_ISSUED",
    actor: "researcher",
    occurred_at: "2026-07-17T16:51:22Z",
    payload: { proposal_id: DEMO_PROPOSAL_ID, state: "RESERVED" },
  },
];

export function createDemoApi(): ConsoleApi {
  return {
    async health() {
      return { status: "ready" };
    },
    async simulate(policy, proposal) {
      const p = policy as { emergency_stop?: boolean; per_transaction_cap?: number };
      const request = proposal as { amount?: number };
      const reasons = [
        ...(p.emergency_stop ? ["EMERGENCY_STOP"] : []),
        ...(Number(request.amount) > Number(p.per_transaction_cap) ? ["PER_TRANSACTION_CAP"] : []),
      ];
      return {
        verdict: reasons.length ? "DENY" : "ALLOW",
        reason_codes: reasons,
        policy_hash: `0x${"a9".repeat(32)}`,
      } satisfies PolicySimulation;
    },
    async proposal(id) {
      return {
        proposal_id: id,
        state: "RESERVED",
        state_version: 1,
        reason_codes: [],
        reservation_id: "0198f1c1-2b3c-7000-8000-000000000303",
      } satisfies ProposalStatus;
    },
    async startExperiment(request: ExperimentRequest) {
      return { ...completedExperiment, seed: request.seed };
    },
    async experiment(id) {
      return { ...completedExperiment, experiment_id: id };
    },
    async verifyEvidence(_kind, artifact) {
      const valid = Boolean(artifact && typeof artifact === "object");
      return {
        valid,
        signer_identity: "spiffe://aegisledger.dev/policy-service",
        errors: valid ? [] : ["artifact is empty"],
      } satisfies AttestationResult;
    },
    async auditEvents() {
      return auditEvents;
    },
  };
}
