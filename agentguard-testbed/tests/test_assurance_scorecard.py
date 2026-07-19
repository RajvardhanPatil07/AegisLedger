from copy import deepcopy
from datetime import date
from pathlib import Path

from scripts.check_assurance_scorecard import track_readiness, validate_scorecard


def scorecard(status: str = "blocked") -> dict:
    gate = {
        "id": "PUB-01",
        "title": "Owner publication decision",
        "owner": "repository-owner",
        "status": status,
        "review_by": "2026-08-31",
        "evidence": [
            {
                "uri": "README.md",
                "label": "Current publication policy",
                "immutable": False,
            }
        ],
    }
    if status == "blocked":
        gate["blocked_by"] = "Owner decision is not recorded"
    if status == "passed":
        gate["evidence"][0]["verified_at"] = "2026-07-19"
    return {
        "schema_version": "aegisledger.assurance_scorecard.v1",
        "candidate_commit": "a" * 40 if status == "passed" else None,
        "tracks": {
            "research": {"target_score": 10.0, "gates": [deepcopy(gate) | {"id": "RES-01"}]},
            "public_release": {"target_score": 10.0, "gates": [gate]},
            "production_custody": {
                "target_score": 10.0,
                "gates": [deepcopy(gate) | {"id": "PRO-01"}],
            },
        },
    }


def test_well_formed_blocked_scorecard_is_valid_but_not_ready(tmp_path: Path):
    (tmp_path / "README.md").write_text("release policy\n", encoding="utf-8")
    report = scorecard()

    assert validate_scorecard(report, tmp_path, today=date(2026, 7, 19)) == []

    ready, reasons = track_readiness(
        report,
        "public_release",
        tmp_path,
        today=date(2026, 7, 19),
    )
    assert not ready
    assert reasons == ["PUB-01 is blocked"]


def test_validator_rejects_missing_owner_evidence_and_blocker(tmp_path: Path):
    report = scorecard()
    gate = report["tracks"]["public_release"]["gates"][0]
    gate["owner"] = ""
    gate["evidence"] = []
    del gate["blocked_by"]

    errors = validate_scorecard(report, tmp_path, today=date(2026, 7, 19))

    assert "PUB-01 owner must be a non-empty string" in errors
    assert "PUB-01 must reference at least one evidence item" in errors
    assert "PUB-01 blocked status requires blocked_by" in errors


def test_validator_rejects_duplicate_ids_and_missing_local_evidence(tmp_path: Path):
    report = scorecard()
    report["tracks"]["research"]["gates"][0]["id"] = "PUB-01"

    errors = validate_scorecard(report, tmp_path, today=date(2026, 7, 19))

    assert "duplicate gate id PUB-01" in errors
    assert any("path does not exist: README.md" in error for error in errors)


def test_passed_gate_requires_verification_and_current_review_date(tmp_path: Path):
    (tmp_path / "README.md").write_text("release policy\n", encoding="utf-8")
    report = scorecard(status="passed")
    public_gate = report["tracks"]["public_release"]["gates"][0]
    del public_gate["evidence"][0]["verified_at"]
    public_gate["review_by"] = "2026-07-18"

    errors = validate_scorecard(report, tmp_path, today=date(2026, 7, 19))

    assert "PUB-01 passed evidence requires verified_at" in errors
    assert "PUB-01 review is overdue; set status to expired or update evidence" in errors


def test_all_passed_gates_make_track_ready(tmp_path: Path):
    (tmp_path / "README.md").write_text("release policy\n", encoding="utf-8")
    report = scorecard(status="passed")

    ready, reasons = track_readiness(
        report,
        "public_release",
        tmp_path,
        today=date(2026, 7, 19),
    )

    assert ready
    assert reasons == []


def test_unknown_track_and_invalid_status_fail_closed(tmp_path: Path):
    (tmp_path / "README.md").write_text("release policy\n", encoding="utf-8")
    report = scorecard()
    report["tracks"]["public_release"]["gates"][0]["status"] = "almost"

    errors = validate_scorecard(report, tmp_path, today=date(2026, 7, 19))
    assert "PUB-01 status 'almost' is unsupported" in errors

    ready, reasons = track_readiness(report, "unknown", tmp_path, today=date(2026, 7, 19))
    assert not ready
    assert reasons == ["unknown assurance track: unknown"]
