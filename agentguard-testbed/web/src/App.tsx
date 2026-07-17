import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import type { User } from "oidc-client-ts";

import { ApiError, createHttpApi } from "./api";
import { createUserManager } from "./auth";
import {
  createDemoApi,
  DEMO_EXPERIMENT_ID,
  DEMO_PROPOSAL_ID,
  examplePolicy,
  exampleProposal,
} from "./demo";
import type {
  AttestationResult,
  AuditEvent,
  ConsoleApi,
  ConsoleSection,
  ExperimentResult,
  PolicySimulation,
  ProposalStatus,
  ServiceHealth,
} from "./types";

const sections: Array<{ id: ConsoleSection; label: string; eyebrow: string; icon: IconName }> = [
  { id: "overview", label: "Overview", eyebrow: "Control plane", icon: "grid" },
  { id: "policy", label: "Policy Lab", eyebrow: "Preflight", icon: "shield" },
  { id: "transactions", label: "Transactions", eyebrow: "Lifecycle", icon: "activity" },
  { id: "experiments", label: "Experiments", eyebrow: "Evaluation", icon: "flask" },
  { id: "evidence", label: "Evidence", eyebrow: "Audit trail", icon: "fingerprint" },
];

type IconName = "grid" | "shield" | "activity" | "flask" | "fingerprint" | "arrow";

type AppProps = {
  demoMode?: boolean;
};

type Notice = { tone: "info" | "success" | "danger"; message: string } | null;

export function App({ demoMode = import.meta.env.VITE_DEMO_MODE === "true" }: AppProps) {
  const [section, setSection] = useState<ConsoleSection>("overview");
  const [user, setUser] = useState<User | null>(null);
  const [authState, setAuthState] = useState<"loading" | "anonymous" | "ready" | "error">(
    demoMode ? "ready" : "loading",
  );
  const [health, setHealth] = useState<ServiceHealth | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);

  const userManager = useMemo(() => (demoMode ? null : createUserManager()), [demoMode]);
  const api = useMemo<ConsoleApi>(
    () => (demoMode ? createDemoApi() : createHttpApi(() => user?.access_token)),
    [demoMode, user?.access_token],
  );

  useEffect(() => {
    if (!userManager) return;
    let active = true;
    const restore = async () => {
      try {
        const callback = window.location.pathname === "/auth/callback";
        const restored = callback
          ? await userManager.signinRedirectCallback()
          : await userManager.getUser();
        if (!active) return;
        if (callback) window.history.replaceState({}, document.title, "/");
        setUser(restored);
        setAuthState(restored && !restored.expired ? "ready" : "anonymous");
      } catch {
        if (active) setAuthState("error");
      }
    };
    void restore();
    return () => {
      active = false;
    };
  }, [userManager]);

  useEffect(() => {
    let active = true;
    api
      .health()
      .then((next) => active && setHealth(next))
      .catch(() => active && setHealth({ status: "not_ready", reason: "unreachable" }));
    return () => {
      active = false;
    };
  }, [api]);

  useEffect(() => {
    if (!notice) return;
    const timeout = window.setTimeout(() => setNotice(null), 6000);
    return () => window.clearTimeout(timeout);
  }, [notice]);

  const principal = demoMode
    ? "researcher · auditor"
    : String(user?.profile.preferred_username ?? user?.profile.name ?? "authenticated user");

  if (authState !== "ready") {
    return (
      <SignIn
        state={authState}
        health={health}
        onSignIn={() => void userManager?.signinRedirect()}
      />
    );
  }

  const selectSection = (next: ConsoleSection) => {
    setSection(next);
    setMenuOpen(false);
    document.getElementById("main-content")?.focus();
  };

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <aside className={`sidebar ${menuOpen ? "sidebar--open" : ""}`} aria-label="Primary">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <span />
          </span>
          <div>
            <strong>AegisLedger</strong>
            <small>Research console</small>
          </div>
        </div>
        <nav>
          {sections.map((item) => (
            <button
              className={section === item.id ? "nav-item nav-item--active" : "nav-item"}
              key={item.id}
              type="button"
              aria-current={section === item.id ? "page" : undefined}
              onClick={() => selectSection(item.id)}
            >
              <Icon name={item.icon} />
              <span>
                <small>{item.eyebrow}</small>
                {item.label}
              </span>
            </button>
          ))}
        </nav>
        <div className="trust-boundary">
          <span className="trust-boundary__line" />
          <strong>Non-custodial boundary</strong>
          <p>Observation and policy controls only. Signing remains isolated.</p>
        </div>
        <div className="principal">
          <span className="avatar">{principal.slice(0, 1).toUpperCase()}</span>
          <span>
            <strong>{principal}</strong>
            <small>{demoMode ? "Demo identity" : "OIDC session"}</small>
          </span>
          {!demoMode && (
            <button
              className="text-button"
              type="button"
              onClick={() => void userManager?.signoutRedirect()}
            >
              Sign out
            </button>
          )}
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <button
            className="menu-button"
            type="button"
            aria-label="Toggle navigation"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((open) => !open)}
          >
            <span />
            <span />
          </button>
          <div className="environment">
            <span className="environment__label">Environment</span>
            <strong>{demoMode ? "Research demo" : "Local development"}</strong>
          </div>
          <div className="service-strip" aria-label="Runtime status">
            <StatusDot
              label="API"
              state={health?.status === "ready" ? "online" : health ? "offline" : "checking"}
            />
            <StatusDot label="Chain 31337" state="online" />
            <StatusDot label={demoMode ? "Demo auth" : "OIDC"} state="online" />
          </div>
        </header>

        <main id="main-content" tabIndex={-1}>
          {section === "overview" && <Overview demoMode={demoMode} health={health} />}
          {section === "policy" && <PolicyLab api={api} notify={setNotice} />}
          {section === "transactions" && <Transactions api={api} notify={setNotice} />}
          {section === "experiments" && <Experiments api={api} notify={setNotice} />}
          {section === "evidence" && <Evidence api={api} notify={setNotice} />}
        </main>
      </div>
      <div className="notice-region" aria-live="polite" aria-atomic="true">
        {notice && <div className={`notice notice--${notice.tone}`}>{notice.message}</div>}
      </div>
    </div>
  );
}

function SignIn({
  state,
  health,
  onSignIn,
}: {
  state: "loading" | "anonymous" | "error";
  health: ServiceHealth | null;
  onSignIn: () => void;
}) {
  return (
    <main className="signin-shell">
      <section className="signin-card" aria-labelledby="signin-title">
        <div className="brand brand--dark">
          <span className="brand-mark" aria-hidden="true">
            <span />
          </span>
          <div>
            <strong>AegisLedger</strong>
            <small>Research console</small>
          </div>
        </div>
        <p className="kicker">IDENTITY-GATED CONTROL PLANE</p>
        <h1 id="signin-title">Wallet autonomy needs a visible boundary.</h1>
        <p className="lede">
          Inspect decisions, rehearse policy changes, and preserve evidence without crossing the
          isolated signing boundary.
        </p>
        {state === "error" && (
          <p className="inline-error" role="alert">
            The identity callback could not be verified. Start a fresh sign-in.
          </p>
        )}
        <button className="button button--primary button--wide" type="button" onClick={onSignIn}>
          {state === "loading" ? "Restoring session…" : "Continue with Keycloak"}
          <Icon name="arrow" />
        </button>
        <div className="signin-foot">
          <StatusDot
            label={health?.status === "ready" ? "API ready" : "Checking API"}
            state={health?.status === "ready" ? "online" : "checking"}
          />
          <span>Authorization code + PKCE</span>
        </div>
      </section>
      <aside className="signin-aside" aria-label="Security architecture summary">
        <span>01</span>
        <h2>Policy before privilege.</h2>
        <p>Every proposed action is evaluated against versioned constraints before signing.</p>
        <span>02</span>
        <h2>Evidence after execution.</h2>
        <p>Decisions and attestations remain independently verifiable.</p>
      </aside>
    </main>
  );
}

function PageHeading({ kicker, title, description, action }: {
  kicker: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <p className="kicker">{kicker}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-heading__action">{action}</div>}
    </div>
  );
}

function Overview({ demoMode, health }: { demoMode: boolean; health: ServiceHealth | null }) {
  return (
    <>
      <PageHeading
        kicker="CONTROL PLANE / RUNTIME + RETAINED BASELINE"
        title="A quiet system is a system you can inspect."
        description="Runtime availability alongside retained policy, evaluation, and evidence results. Aggregate figures are research artifacts, not live production telemetry."
        action={<span className="snapshot-time">Retained baseline · 17 Jul 2026</span>}
      />
      <section className="metric-grid" aria-label="Security posture metrics">
        <Metric label="Reference policy" value="Enforced" detail="Two-approval activation" tone="good" />
        <Metric label="Evaluation corpus" value="1,284" detail="Retained proposal outcomes" />
        <Metric label="Attack success" value="0.8%" detail="Retained 95% CI · 0.3–1.7%" tone="good" />
        <Metric label="Evidence coverage" value="100%" detail="Retained signed records" tone="good" />
      </section>
      <div className="overview-grid">
        <section className="panel posture-panel" aria-labelledby="posture-title">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">REFERENCE DEFENSE POSTURE</p>
              <h2 id="posture-title">Guardrails are holding</h2>
            </div>
            <span className="score">94</span>
          </div>
          <div className="posture-scale" role="img" aria-label="Security posture score 94 out of 100">
            <span style={{ width: "94%" }} />
          </div>
          <div className="control-list">
            <ControlRow label="Default-deny policy" state="Enforced" />
            <ControlRow label="Two-person activation" state="Enforced" />
            <ControlRow label="Isolated signer" state="Attested" />
            <ControlRow label="Replay protection" state="Enforced" />
          </div>
        </section>
        <section className="panel flow-panel" aria-labelledby="flow-title">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">RETAINED EVALUATION</p>
              <h2 id="flow-title">Decision flow</h2>
            </div>
            <span className="subtle">1,284 evaluated</span>
          </div>
          <div className="flow-bar" role="img" aria-label="Decision outcomes">
            <span className="flow-bar__allow" style={{ width: "72%" }} />
            <span className="flow-bar__deny" style={{ width: "21%" }} />
            <span className="flow-bar__expire" style={{ width: "7%" }} />
          </div>
          <div className="legend">
            <span><i className="allow" />Allow <strong>925</strong></span>
            <span><i className="deny" />Deny <strong>270</strong></span>
            <span><i className="expire" />Expired <strong>89</strong></span>
          </div>
          <div className="callout">
            <Icon name="shield" />
            <p><strong>Four hostile scenarios contained.</strong> Latest seeded replay produced no material loss.</p>
          </div>
        </section>
        <section className="panel runtime-panel" aria-labelledby="runtime-title">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">RUNTIME</p>
              <h2 id="runtime-title">Trust boundary</h2>
            </div>
          </div>
          <dl className="runtime-list">
            <div><dt>API</dt><dd>{health?.status ?? "checking"}</dd></div>
            <div><dt>Identity</dt><dd>{demoMode ? "demo adapter" : "OIDC / PKCE"}</dd></div>
            <div><dt>Chain</dt><dd>31337 · Anvil</dd></div>
            <div><dt>Signer</dt><dd>isolated · mTLS</dd></div>
          </dl>
        </section>
      </div>
    </>
  );
}

function PolicyLab({ api, notify }: PanelProps) {
  const [policy, setPolicy] = useState(() => JSON.stringify(examplePolicy(), null, 2));
  const [proposal, setProposal] = useState(() => JSON.stringify(exampleProposal(), null, 2));
  const [result, setResult] = useState<PolicySimulation | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const next = await api.simulate(JSON.parse(policy), JSON.parse(proposal));
      setResult(next);
      notify({
        tone: next.verdict === "ALLOW" ? "success" : "danger",
        message: `Simulation complete: ${next.verdict}`,
      });
    } catch (error) {
      notify(errorNotice(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeading
        kicker="POLICY LAB / SIDE-EFFECT FREE"
        title="Rehearse the decision before it matters."
        description="Evaluate a proposed action against a candidate policy. Simulation creates no reservation and cannot reach the signer."
        action={<span className="boundary-badge"><Icon name="shield" /> No signing path</span>}
      />
      <form className="lab-grid" onSubmit={submit}>
        <JsonEditor label="Candidate policy" value={policy} onChange={setPolicy} />
        <JsonEditor label="Proposed action" value={proposal} onChange={setProposal} />
        <div className="lab-actions">
          <p>Strict schemas · deterministic policy hash · no state mutation</p>
          <button className="button button--primary" type="submit" disabled={busy}>
            {busy ? "Evaluating…" : "Run simulation"}
            <Icon name="arrow" />
          </button>
        </div>
      </form>
      {result && (
        <section className={`result-card result-card--${result.verdict.toLowerCase()}`} aria-live="polite">
          <div>
            <p className="eyebrow">POLICY VERDICT</p>
            <strong>{result.verdict}</strong>
          </div>
          <dl>
            <div><dt>Reason codes</dt><dd>{result.reason_codes.join(", ") || "No denial reasons"}</dd></div>
            <div><dt>Policy hash</dt><dd className="mono">{result.policy_hash}</dd></div>
          </dl>
        </section>
      )}
    </>
  );
}

function Transactions({ api, notify }: PanelProps) {
  const [id, setId] = useState(DEMO_PROPOSAL_ID);
  const [result, setResult] = useState<ProposalStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const lifecycle = ["PROPOSED", "RESERVED", "SIGNED", "SUBMITTED", "SETTLED"];
  const currentIndex = result ? lifecycle.indexOf(result.state) : -1;

  const lookup = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      setResult(await api.proposal(id.trim()));
    } catch (error) {
      notify(errorNotice(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeading
        kicker="TRANSACTIONS / LIFECYCLE INSPECTION"
        title="Follow the state, never the story."
        description="Resolve a proposal by identifier and inspect its monotonic lifecycle, reservation, and policy reason codes."
      />
      <section className="panel lookup-panel">
        <form className="lookup-form" onSubmit={lookup}>
          <label htmlFor="proposal-id">Proposal ID</label>
          <div>
            <input id="proposal-id" value={id} onChange={(event) => setId(event.target.value)} required />
            <button className="button button--primary" type="submit" disabled={busy}>
              {busy ? "Resolving…" : "Inspect lifecycle"}
            </button>
          </div>
        </form>
      </section>
      {result ? (
        <section className="panel transaction-result" aria-live="polite">
          <div className="panel-heading">
            <div><p className="eyebrow">PROPOSAL STATE</p><h2>{result.state}</h2></div>
            <span className="mono subtle">v{result.state_version}</span>
          </div>
          <ol className="lifecycle">
            {lifecycle.map((state, index) => (
              <li className={index <= currentIndex ? "lifecycle__active" : ""} key={state}>
                <span>{index + 1}</span><strong>{state}</strong>
              </li>
            ))}
          </ol>
          <dl className="detail-list">
            <div><dt>Proposal</dt><dd className="mono">{result.proposal_id}</dd></div>
            <div><dt>Reservation</dt><dd className="mono">{result.reservation_id ?? "None"}</dd></div>
            <div><dt>Reason codes</dt><dd>{result.reason_codes.join(", ") || "None"}</dd></div>
          </dl>
        </section>
      ) : (
        <EmptyState icon="activity" title="No proposal resolved" detail="Use a UUIDv7 proposal identifier to load its current state." />
      )}
    </>
  );
}

const scenarioOptions = [
  ["I-composed-injection", "Composed injection"],
  ["II-tool-poisoning", "Tool poisoning"],
  ["III-inbound-asset-permission", "Inbound asset permission"],
  ["IV-mev-extraction", "MEV extraction"],
] as const;

function Experiments({ api, notify }: PanelProps) {
  const [seed, setSeed] = useState("research-baseline-07");
  const [runs, setRuns] = useState(12);
  const [selected, setSelected] = useState<string[]>(scenarioOptions.map(([id]) => id));
  const [result, setResult] = useState<ExperimentResult | null>(null);
  const [replayId, setReplayId] = useState(DEMO_EXPERIMENT_ID);
  const [busy, setBusy] = useState(false);

  const run = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const next = await api.startExperiment({ seed, runs_per_scenario: runs, scenarios: selected });
      setResult(next);
      setReplayId(next.experiment_id);
      notify({ tone: "success", message: `Experiment ${next.status.toLowerCase()}.` });
    } catch (error) {
      notify(errorNotice(error));
    } finally {
      setBusy(false);
    }
  };

  const replay = async () => {
    setBusy(true);
    try {
      setResult(await api.experiment(replayId.trim()));
    } catch (error) {
      notify(errorNotice(error));
    } finally {
      setBusy(false);
    }
  };

  const toggle = (id: string) =>
    setSelected((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );

  return (
    <>
      <PageHeading
        kicker="EXPERIMENTS / REPRODUCIBLE EVALUATION"
        title="Turn an attack claim into a replayable result."
        description="Pin a seed, choose adversarial scenarios, and retain the manifest, raw runs, confidence intervals, and performance summary."
      />
      <div className="experiment-grid">
        <form className="panel experiment-form" onSubmit={run}>
          <div className="panel-heading"><div><p className="eyebrow">NEW RUN</p><h2>Evaluation manifest</h2></div></div>
          <label htmlFor="experiment-seed">Deterministic seed</label>
          <input id="experiment-seed" value={seed} onChange={(event) => setSeed(event.target.value)} required />
          <label htmlFor="experiment-runs">Runs per scenario</label>
          <input id="experiment-runs" type="number" min="1" max="1000" value={runs} onChange={(event) => setRuns(Number(event.target.value))} />
          <fieldset>
            <legend>Adversarial scenarios</legend>
            {scenarioOptions.map(([id, label]) => (
              <label className="check-row" key={id}>
                <input type="checkbox" checked={selected.includes(id)} onChange={() => toggle(id)} />
                <span><strong>{label}</strong><small>{id}</small></span>
              </label>
            ))}
          </fieldset>
          <button className="button button--primary" type="submit" disabled={busy || !selected.length}>
            {busy ? "Running…" : "Start experiment"}<Icon name="arrow" />
          </button>
        </form>
        <section className="panel experiment-result" aria-live="polite">
          <div className="panel-heading">
            <div><p className="eyebrow">REPLAY / COMPARE</p><h2>Result evidence</h2></div>
            {result && <span className={`state-tag state-tag--${result.status.toLowerCase()}`}>{result.status}</span>}
          </div>
          <div className="inline-lookup">
            <label htmlFor="experiment-id">Experiment ID</label>
            <div><input id="experiment-id" value={replayId} onChange={(event) => setReplayId(event.target.value)} /><button className="button button--quiet" type="button" onClick={() => void replay()} disabled={busy}>Load</button></div>
          </div>
          {result ? <ExperimentSummary result={result} /> : <EmptyState icon="flask" title="No result loaded" detail="Start a seeded run or load a retained experiment ID." compact />}
        </section>
      </div>
    </>
  );
}

function ExperimentSummary({ result }: { result: ExperimentResult }) {
  const summary = result.summary ?? {};
  const performance = (summary.performance ?? {}) as Record<string, unknown>;
  return (
    <div className="summary-stack">
      <dl className="mini-metrics">
        <div><dt>Raw runs</dt><dd>{readNumber(summary.raw_run_count)}</dd></div>
        <div><dt>False positives</dt><dd>{formatPercent(summary.false_positive_rate)}</dd></div>
        <div><dt>Throughput</dt><dd>{readNumber(performance.throughput_runs_per_second)} /s</dd></div>
      </dl>
      <dl className="detail-list">
        <div><dt>Seed</dt><dd>{result.seed}</dd></div>
        <div><dt>Configuration hash</dt><dd className="mono hash-wrap">{result.configuration_hash}</dd></div>
        <div><dt>Artifact</dt><dd className="mono">{result.result_uri ?? "Pending"}</dd></div>
      </dl>
    </div>
  );
}

function Evidence({ api, notify }: PanelProps) {
  const [kind, setKind] = useState<"decision" | "attestation">("decision");
  const [artifact, setArtifact] = useState("{}");
  const [verification, setVerification] = useState<AttestationResult | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [busy, setBusy] = useState(false);

  const verify = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      const next = await api.verifyEvidence(kind, JSON.parse(artifact));
      setVerification(next);
      notify({ tone: next.valid ? "success" : "danger", message: next.valid ? "Evidence is valid." : "Evidence verification failed." });
    } catch (error) {
      notify(errorNotice(error));
    } finally {
      setBusy(false);
    }
  };

  const loadAudit = async () => {
    setBusy(true);
    try {
      setEvents(await api.auditEvents());
    } catch (error) {
      notify(errorNotice(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeading
        kicker="EVIDENCE / INDEPENDENT VERIFICATION"
        title="Trust the artifact, not the operator."
        description="Verify signed policy decisions or complete attestations, then inspect the append-only audit stream."
      />
      <div className="evidence-grid">
        <form className="panel evidence-form" onSubmit={verify}>
          <div className="panel-heading"><div><p className="eyebrow">VERIFIER</p><h2>Artifact check</h2></div></div>
          <fieldset className="segmented">
            <legend className="sr-only">Evidence type</legend>
            <label><input type="radio" name="evidence-kind" checked={kind === "decision"} onChange={() => setKind("decision")} /><span>Decision token</span></label>
            <label><input type="radio" name="evidence-kind" checked={kind === "attestation"} onChange={() => setKind("attestation")} /><span>Complete attestation</span></label>
          </fieldset>
          <JsonEditor label="Artifact JSON" value={artifact} onChange={setArtifact} compact />
          <button className="button button--primary" type="submit" disabled={busy}>{busy ? "Verifying…" : "Verify evidence"}</button>
          {verification && (
            <div className={`verification verification--${verification.valid ? "valid" : "invalid"}`} aria-live="polite">
              <strong>{verification.valid ? "Cryptographically valid" : "Verification failed"}</strong>
              <span>{verification.signer_identity}</span>
              {verification.errors.map((error) => <small key={error}>{error}</small>)}
            </div>
          )}
        </form>
        <section className="panel audit-panel">
          <div className="panel-heading">
            <div><p className="eyebrow">APPEND-ONLY JOURNAL</p><h2>Audit events</h2></div>
            <button className="button button--quiet" type="button" disabled={busy} onClick={() => void loadAudit()}>Load stream</button>
          </div>
          {events.length ? (
            <div className="table-scroll">
              <table>
                <caption className="sr-only">Audit journal events</caption>
                <thead><tr><th>Seq.</th><th>Event</th><th>Actor</th><th>Time</th></tr></thead>
                <tbody>{events.map((event) => (
                  <tr key={event.sequence}><td className="mono">{event.sequence}</td><td>{event.event_type.replaceAll("_", " ")}</td><td>{event.actor}</td><td>{new Date(event.occurred_at).toLocaleString()}</td></tr>
                ))}</tbody>
              </table>
            </div>
          ) : <EmptyState icon="fingerprint" title="Audit stream not loaded" detail="Auditor authorization is required to read journal evidence." compact />}
        </section>
      </div>
    </>
  );
}

type PanelProps = { api: ConsoleApi; notify: (notice: Notice) => void };

function JsonEditor({ label, value, onChange, compact = false }: { label: string; value: string; onChange: (value: string) => void; compact?: boolean }) {
  const id = label.toLowerCase().replaceAll(" ", "-");
  return (
    <section className={`json-editor ${compact ? "json-editor--compact" : ""}`}>
      <div className="json-editor__heading"><label htmlFor={id}>{label}</label><span>JSON</span></div>
      <textarea id={id} spellCheck="false" value={value} onChange={(event) => onChange(event.target.value)} />
    </section>
  );
}

function Metric({ label, value, detail, tone }: { label: string; value: string; detail: string; tone?: "good" }) {
  return <article className="metric"><span>{label}</span><strong className={tone === "good" ? "good" : ""}>{value}</strong><small>{detail}</small></article>;
}

function ControlRow({ label, state }: { label: string; state: string }) {
  return <div><span className="control-check" aria-hidden="true">✓</span><span>{label}</span><strong>{state}</strong></div>;
}

function EmptyState({ icon, title, detail, compact = false }: { icon: IconName; title: string; detail: string; compact?: boolean }) {
  return <section className={`empty-state ${compact ? "empty-state--compact" : ""}`}><Icon name={icon} /><h2>{title}</h2><p>{detail}</p></section>;
}

function StatusDot({ label, state }: { label: string; state: "online" | "offline" | "checking" }) {
  return <span className={`status status--${state}`}><i aria-hidden="true" />{label}</span>;
}

function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /></>,
    shield: <path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3Zm-3 9 2 2 4-5" />,
    activity: <path d="M3 12h4l2.5-6 5 12 2.5-6h4" />,
    flask: <path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3M8 15h8" />,
    fingerprint: <path d="M12 11a3 3 0 0 1 3 3c0 3-1 5-2 7M8 21c1-2 1-4 1-7a3 3 0 0 1 6 0M5 18c.5-1.5.5-2.5.5-4a6.5 6.5 0 0 1 13 0c0 2-.2 4-1 6M5 9a8 8 0 0 1 14-2M3 14v-1" />,
    arrow: <path d="M5 12h14m-5-5 5 5-5 5" />,
  };
  return <svg className="icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>;
}

function errorNotice(error: unknown): NonNullable<Notice> {
  if (error instanceof SyntaxError) return { tone: "danger", message: "The editor contains invalid JSON." };
  if (error instanceof ApiError) return { tone: "danger", message: `${error.code}: ${error.message}` };
  return { tone: "danger", message: "The operation could not be completed." };
}

function readNumber(value: unknown): string {
  return typeof value === "number" ? value.toLocaleString() : "—";
}

function formatPercent(value: unknown): string {
  return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "—";
}
