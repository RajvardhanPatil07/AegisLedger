import { useState, type FormEvent } from "react";

import { errorNotice, type Notice } from "../notice";
import type { AttestationResult, AuditEvent, ConsoleApi } from "../types";
import { EmptyState, JsonEditor, PageHeading } from "./ui";

type EvidenceProps = {
  api: ConsoleApi;
  canReadAudit: boolean;
  initialProposalId: string;
  notify: (notice: Notice) => void;
};

export function Evidence({ api, canReadAudit, initialProposalId, notify }: EvidenceProps) {
  const [kind, setKind] = useState<"decision" | "attestation">("decision");
  const [proposalId, setProposalId] = useState(initialProposalId);
  const [artifact, setArtifact] = useState("{}");
  const [verification, setVerification] = useState<AttestationResult | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [busy, setBusy] = useState(false);

  const showVerification = (next: AttestationResult) => {
    setVerification(next);
    notify({
      tone: next.valid ? "success" : "danger",
      message: next.valid ? "Evidence is valid." : "Evidence verification failed.",
    });
  };

  const loadAttestation = async () => {
    setBusy(true);
    try {
      const retained = await api.attestation(proposalId.trim());
      setKind("attestation");
      setArtifact(JSON.stringify(retained, null, 2));
      showVerification(await api.verifyEvidence("attestation", retained));
    } catch (error) {
      notify(errorNotice(error));
    } finally {
      setBusy(false);
    }
  };

  const verify = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      showVerification(await api.verifyEvidence(kind, JSON.parse(artifact)));
    } catch (error) {
      notify(errorNotice(error));
    } finally {
      setBusy(false);
    }
  };

  const loadAudit = async () => {
    if (!canReadAudit) return;
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
        description="Load retained settlement evidence by proposal, verify it without mutable service state, or inspect the append-only audit stream."
      />
      <div className="evidence-grid">
        <form className="panel evidence-form" onSubmit={verify}>
          <div className="panel-heading">
            <div>
              <p className="eyebrow">VERIFIER</p>
              <h2>Artifact check</h2>
            </div>
          </div>
          <div className="inline-lookup evidence-lookup">
            <label htmlFor="attestation-proposal-id">Settled proposal ID</label>
            <div>
              <input
                id="attestation-proposal-id"
                value={proposalId}
                onChange={(event) => setProposalId(event.target.value)}
                required
              />
              <button
                className="button button--quiet"
                type="button"
                disabled={busy || !proposalId.trim()}
                onClick={() => void loadAttestation()}
              >
                Load &amp; verify
              </button>
            </div>
          </div>
          <fieldset className="segmented">
            <legend className="sr-only">Evidence type</legend>
            <label>
              <input
                type="radio"
                name="evidence-kind"
                checked={kind === "decision"}
                onChange={() => setKind("decision")}
              />
              <span>Decision token</span>
            </label>
            <label>
              <input
                type="radio"
                name="evidence-kind"
                checked={kind === "attestation"}
                onChange={() => setKind("attestation")}
              />
              <span>Complete attestation</span>
            </label>
          </fieldset>
          <JsonEditor label="Artifact JSON" value={artifact} onChange={setArtifact} compact />
          <button className="button button--primary" type="submit" disabled={busy}>
            {busy ? "Verifying…" : "Verify evidence"}
          </button>
          {verification && (
            <div
              className={`verification verification--${verification.valid ? "valid" : "invalid"}`}
              aria-live="polite"
            >
              <strong>
                {verification.valid ? "Cryptographically valid" : "Verification failed"}
              </strong>
              <span>{verification.signer_identity}</span>
              {verification.errors.map((error) => (
                <small key={error}>{error}</small>
              ))}
            </div>
          )}
        </form>
        <section className="panel audit-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">APPEND-ONLY JOURNAL</p>
              <h2>Audit events</h2>
            </div>
            <button
              className="button button--quiet"
              type="button"
              disabled={busy || !canReadAudit}
              onClick={() => void loadAudit()}
            >
              Load stream
            </button>
          </div>
          {events.length ? (
            <div className="table-scroll">
              <table>
                <caption className="sr-only">Audit journal events</caption>
                <thead>
                  <tr>
                    <th>Seq.</th>
                    <th>Event</th>
                    <th>Actor</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event) => (
                    <tr key={event.sequence}>
                      <td className="mono">{event.sequence}</td>
                      <td>{event.event_type.replaceAll("_", " ")}</td>
                      <td>{event.actor}</td>
                      <td>{new Date(event.occurred_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon="fingerprint"
              title={canReadAudit ? "Audit stream not loaded" : "Auditor role required"}
              detail={
                canReadAudit
                  ? "Load the retained journal to inspect append-only evidence."
                  : "Your current role cannot read the audit journal. Sign in with the local auditor account to continue."
              }
              compact
            />
          )}
        </section>
      </div>
    </>
  );
}
