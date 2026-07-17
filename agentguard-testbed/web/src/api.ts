import type {
  AttestationResult,
  AuditEvent,
  ConsoleApi,
  ExperimentRequest,
  ExperimentResult,
  PolicySimulation,
  ProposalStatus,
  ServiceHealth,
} from "./types";

type AccessToken = () => string | undefined;

type ApiErrorBody = {
  error?: {
    code?: string;
    message?: string;
  };
};

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  accessToken: AccessToken,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  const token = accessToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body) headers.set("Content-Type", "application/json");

  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let body: ApiErrorBody = {};
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      // The status line is still useful when a proxy returns a non-JSON error.
    }
    throw new ApiError(
      body.error?.message ?? `Request failed with status ${response.status}`,
      response.status,
      body.error?.code ?? "REQUEST_FAILED",
    );
  }
  return (await response.json()) as T;
}

function parseServerSentEvents(source: string): AuditEvent[] {
  return source
    .split("\n\n")
    .map((frame) => frame.split("\n").find((line) => line.startsWith("data: ")))
    .filter((line): line is string => Boolean(line))
    .map((line) => JSON.parse(line.slice(6)) as AuditEvent);
}

export function createHttpApi(accessToken: AccessToken): ConsoleApi {
  return {
    health: () => request<ServiceHealth>("/health/ready", accessToken),
    simulate: (policy, proposal) =>
      request<PolicySimulation>("/api/v1/policies/simulations", accessToken, {
        method: "POST",
        body: JSON.stringify({ policy, proposal }),
      }),
    proposal: (id) =>
      request<ProposalStatus>(`/api/v1/proposals/${encodeURIComponent(id)}`, accessToken),
    startExperiment: (body: ExperimentRequest) =>
      request<ExperimentResult>("/api/v1/experiments", accessToken, {
        method: "POST",
        body: JSON.stringify(body),
      }),
    experiment: (id) =>
      request<ExperimentResult>(`/api/v1/experiments/${encodeURIComponent(id)}`, accessToken),
    verifyEvidence: (kind, artifact) =>
      request<AttestationResult>("/api/v1/attestations/verifications", accessToken, {
        method: "POST",
        body: JSON.stringify({ [kind]: artifact }),
      }),
    async auditEvents() {
      const headers = new Headers();
      const token = accessToken();
      if (token) headers.set("Authorization", `Bearer ${token}`);
      const response = await fetch("/api/v1/audit/events/stream", { headers });
      if (!response.ok) {
        throw new ApiError("Unable to read the audit stream", response.status, "AUDIT_FAILED");
      }
      return parseServerSentEvents(await response.text());
    },
  };
}
