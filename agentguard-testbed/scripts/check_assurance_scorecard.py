#!/usr/bin/env python3
"""Validate the evidence-backed AegisLedger assurance scorecard."""

from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCHEMA_VERSION = "aegisledger.assurance_scorecard.v1"
TRACKS = {
    "research": "RES",
    "public_release": "PUB",
    "production_custody": "PRO",
}
STATUSES = {"pending", "in_progress", "blocked", "passed", "failed", "expired"}


def validate_scorecard(
    scorecard: dict[str, Any],
    repository_root: Path,
    *,
    today: date,
) -> list[str]:
    """Return all schema, freshness, ownership, and evidence errors."""
    errors: list[str] = []
    if scorecard.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")

    candidate_commit = scorecard.get("candidate_commit")
    if candidate_commit is not None and (
        not isinstance(candidate_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", candidate_commit) is None
    ):
        errors.append("candidate_commit must be null or a lowercase 40-character Git SHA")

    tracks = scorecard.get("tracks")
    if not isinstance(tracks, dict):
        return [*errors, "tracks must be an object"]
    missing_tracks = sorted(set(TRACKS) - set(tracks))
    extra_tracks = sorted(set(tracks) - set(TRACKS))
    if missing_tracks:
        errors.append(f"missing assurance tracks: {', '.join(missing_tracks)}")
    if extra_tracks:
        errors.append(f"unsupported assurance tracks: {', '.join(extra_tracks)}")

    seen_ids: set[str] = set()
    for track_name, prefix in TRACKS.items():
        track = tracks.get(track_name)
        if not isinstance(track, dict):
            continue
        if track.get("target_score") != 10.0:
            errors.append(f"{track_name} target_score must be 10.0")
        gates = track.get("gates")
        if not isinstance(gates, list) or not gates:
            errors.append(f"{track_name} must contain at least one gate")
            continue
        for index, gate in enumerate(gates, start=1):
            if not isinstance(gate, dict):
                errors.append(f"{track_name} gate {index} must be an object")
                continue
            gate_id = gate.get("id")
            label = gate_id if isinstance(gate_id, str) and gate_id else f"{track_name}[{index}]"
            if not isinstance(gate_id, str) or re.fullmatch(rf"{prefix}-\d{{2}}", gate_id) is None:
                errors.append(f"{label} id must match {prefix}-NN")
            if isinstance(gate_id, str) and gate_id:
                if gate_id in seen_ids:
                    errors.append(f"duplicate gate id {gate_id}")
                seen_ids.add(gate_id)
            _validate_gate(gate, label, repository_root, today, errors)
    return errors


def _validate_gate(
    gate: dict[str, Any],
    label: str,
    repository_root: Path,
    today: date,
    errors: list[str],
) -> None:
    for field in ("title", "owner"):
        if not isinstance(gate.get(field), str) or not gate[field].strip():
            errors.append(f"{label} {field} must be a non-empty string")

    status = gate.get("status")
    if status not in STATUSES:
        errors.append(f"{label} status {status!r} is unsupported")
    if status == "blocked" and (
        not isinstance(gate.get("blocked_by"), str) or not gate["blocked_by"].strip()
    ):
        errors.append(f"{label} blocked status requires blocked_by")

    review_by = _parse_date(gate.get("review_by"), f"{label} review_by", errors)
    if review_by is not None and review_by < today and status != "expired":
        errors.append(f"{label} review is overdue; set status to expired or update evidence")

    evidence = gate.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{label} must reference at least one evidence item")
        return
    for index, item in enumerate(evidence, start=1):
        if not isinstance(item, dict):
            errors.append(f"{label} evidence {index} must be an object")
            continue
        item_label = f"{label} evidence {index}"
        uri = item.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            errors.append(f"{item_label} uri must be a non-empty string")
        else:
            _validate_evidence_uri(uri, item_label, repository_root, errors)
        if not isinstance(item.get("label"), str) or not item["label"].strip():
            errors.append(f"{item_label} label must be a non-empty string")
        if not isinstance(item.get("immutable"), bool):
            errors.append(f"{item_label} immutable must be boolean")
        if status == "passed":
            if "verified_at" not in item:
                errors.append(f"{label} passed evidence requires verified_at")
            else:
                verified_at = _parse_date(
                    item.get("verified_at"),
                    f"{item_label} verified_at",
                    errors,
                )
                if verified_at is not None and verified_at > today:
                    errors.append(f"{item_label} verified_at cannot be in the future")


def _validate_evidence_uri(
    uri: str,
    label: str,
    repository_root: Path,
    errors: list[str],
) -> None:
    if urlparse(uri).scheme:
        return
    candidate = (repository_root / uri).resolve()
    root = repository_root.resolve()
    if not candidate.is_relative_to(root):
        errors.append(f"{label} path escapes repository root: {uri}")
    elif not candidate.exists():
        errors.append(f"{label} path does not exist: {uri}")


def _parse_date(value: object, label: str, errors: list[str]) -> date | None:
    if not isinstance(value, str):
        errors.append(f"{label} must use YYYY-MM-DD")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        errors.append(f"{label} must use YYYY-MM-DD")
        return None


def track_readiness(
    scorecard: dict[str, Any],
    track_name: str,
    repository_root: Path,
    *,
    today: date,
) -> tuple[bool, list[str]]:
    """Return whether every gate in a track is current and passed."""
    if track_name not in TRACKS:
        return False, [f"unknown assurance track: {track_name}"]
    errors = validate_scorecard(scorecard, repository_root, today=today)
    if errors:
        return False, errors
    gates = scorecard["tracks"][track_name]["gates"]
    reasons = [f"{gate['id']} is {gate['status']}" for gate in gates if gate["status"] != "passed"]
    if reasons:
        return False, reasons
    candidate_commit = scorecard.get("candidate_commit")
    if not isinstance(candidate_commit, str):
        return False, ["candidate_commit is required before a track can be ready"]
    return not reasons, reasons


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    parser.add_argument("--scorecard", type=Path)
    parser.add_argument("--require-track", choices=tuple(TRACKS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repository_root = args.repository_root.resolve()
    scorecard_path = args.scorecard or (
        repository_root / "agentguard-testbed" / "docs" / "assurance-scorecard.json"
    )
    value = json.loads(scorecard_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("assurance scorecard must be a JSON object")
    if args.require_track:
        passed, messages = track_readiness(
            value,
            args.require_track,
            repository_root,
            today=date.today(),
        )
    else:
        messages = validate_scorecard(value, repository_root, today=date.today())
        passed = not messages
    for message in messages:
        print(f"ERROR: {message}")
    if passed:
        suffix = f" and {args.require_track} is ready" if args.require_track else ""
        print(f"Assurance scorecard is valid{suffix}.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
