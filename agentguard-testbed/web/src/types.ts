export type ConsoleSection =
  | "overview"
  | "policy"
  | "transactions"
  | "experiments"
  | "evidence";

export type ServiceHealth = {
  status: "ready" | "not_ready" | "ok";
  reason?: string;
};

export type PolicySimulation = {
  verdict: "ALLOW" | "DENY";
  reason_codes: string[];
  policy_hash: string;
};

export type ProposalStatus = {
  proposal_id: string;
  state:
    | "PROPOSED"
    | "RESERVED"
    | "SIGNED"
    | "SUBMITTED"
    | "SETTLED"
    | "DENIED"
    | "REVERTED"
    | "EXPIRED";
  state_version: number;
  reason_codes: string[];
  reservation_id: string | null;
};

export type ExperimentResult = {
  experiment_id: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  seed: string;
  configuration_hash: string;
  result_uri: string | null;
  summary: Record<string, unknown> | null;
  error: string | null;
};

export type AttestationResult = {
  valid: boolean;
  signer_identity: string;
  errors: string[];
};

export type AuditEvent = {
  sequence: number;
  event_type: string;
  actor: string;
  occurred_at: string;
  payload: Record<string, unknown>;
};

export type ExperimentRequest = {
  seed: string;
  runs_per_scenario: number;
  scenarios: string[];
};

export interface ConsoleApi {
  health(): Promise<ServiceHealth>;
  simulate(policy: unknown, proposal: unknown): Promise<PolicySimulation>;
  proposal(id: string): Promise<ProposalStatus>;
  startExperiment(request: ExperimentRequest): Promise<ExperimentResult>;
  experiment(id: string): Promise<ExperimentResult>;
  verifyEvidence(kind: "decision" | "attestation", artifact: unknown): Promise<AttestationResult>;
  auditEvents(): Promise<AuditEvent[]>;
}
