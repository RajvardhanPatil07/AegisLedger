from copy import deepcopy
from pathlib import Path

from scripts.check_provenance_inventory import (
    release_readiness,
    validate_inventory,
)


def inventory(status: str = "verified") -> dict:
    return {
        "schema_version": "aegisledger.provenance.v1",
        "owner": "repository-owner",
        "last_reviewed": "2026-07-19",
        "current_entries": [
            {
                "id": "SRC-001",
                "title": "Repository-authored files",
                "patterns": ["README.md"],
                "origin": "repository_authored",
                "status": status,
                "copyright_holder": "Rajvardhan Patil",
                "license": "Apache-2.0",
                "evidence": [
                    {
                        "uri": "NOTICE",
                        "label": "Repository copyright notice",
                    }
                ],
            }
        ],
        "history_entries": [],
    }


def test_valid_inventory_covers_every_tracked_file(tmp_path: Path):
    (tmp_path / "README.md").write_text("project\n", encoding="utf-8")
    (tmp_path / "NOTICE").write_text("copyright\n", encoding="utf-8")
    report = inventory()

    assert validate_inventory(
        report,
        tmp_path,
        ["README.md"],
        history_object_exists=lambda _commit, _path: True,
    ) == []
    ready, reasons = release_readiness(
        report,
        tmp_path,
        ["README.md"],
        history_object_exists=lambda _commit, _path: True,
    )
    assert ready
    assert reasons == []


def test_uncovered_tracked_file_fails_validation(tmp_path: Path):
    (tmp_path / "NOTICE").write_text("copyright\n", encoding="utf-8")
    report = inventory()

    errors = validate_inventory(report, tmp_path, ["README.md", "src/new.py"])

    assert "tracked file is missing provenance coverage: src/new.py" in errors


def test_overlapping_provenance_groups_fail_validation(tmp_path: Path):
    (tmp_path / "NOTICE").write_text("copyright\n", encoding="utf-8")
    report = inventory()
    duplicate = deepcopy(report["current_entries"][0])
    duplicate["id"] = "SRC-002"
    report["current_entries"].append(duplicate)

    errors = validate_inventory(report, tmp_path, ["README.md"])

    assert (
        "tracked file has ambiguous provenance coverage: README.md "
        "(SRC-001, SRC-002)"
    ) in errors


def test_owner_confirmation_blocks_release_without_invalidating_inventory(tmp_path: Path):
    (tmp_path / "NOTICE").write_text("copyright\n", encoding="utf-8")
    report = inventory(status="owner_confirmation_required")

    assert validate_inventory(report, tmp_path, ["README.md"]) == []

    ready, reasons = release_readiness(report, tmp_path, ["README.md"])
    assert not ready
    assert reasons == ["SRC-001 requires owner confirmation"]


def test_historical_public_material_requires_a_commit_and_clearance(tmp_path: Path):
    (tmp_path / "NOTICE").write_text("copyright\n", encoding="utf-8")
    report = inventory()
    report["history_entries"] = [
        {
            "id": "HIST-001",
            "title": "Deleted design prompt",
            "path": "Design-Prompt.md",
            "introduced_commit": "a" * 40,
            "origin": "repository_authored",
            "status": "owner_confirmation_required",
            "copyright_holder": "Rajvardhan Patil",
            "license": "Apache-2.0",
            "evidence": [
                {
                    "uri": "git+commit:a" + ("a" * 39) + ":Design-Prompt.md",
                    "label": "Original Git object",
                }
            ],
        }
    ]

    assert validate_inventory(
        report,
        tmp_path,
        ["README.md"],
        history_object_exists=lambda _commit, _path: True,
    ) == []
    ready, reasons = release_readiness(
        report,
        tmp_path,
        ["README.md"],
        history_object_exists=lambda _commit, _path: True,
    )
    assert not ready
    assert reasons == ["HIST-001 requires owner confirmation"]

    invalid = deepcopy(report)
    invalid["history_entries"][0]["introduced_commit"] = "deadbeef"
    errors = validate_inventory(
        invalid,
        tmp_path,
        ["README.md"],
        history_object_exists=lambda _commit, _path: True,
    )
    assert "HIST-001 introduced_commit must be a lowercase 40-character Git SHA" in errors

    missing = validate_inventory(
        report,
        tmp_path,
        ["README.md"],
        history_object_exists=lambda _commit, _path: False,
    )
    assert (
        "HIST-001 historical object is not present: "
        + ("a" * 40)
        + ":Design-Prompt.md"
    ) in missing


def test_verified_third_party_entry_requires_source_attribution(tmp_path: Path):
    report = inventory()
    entry = report["current_entries"][0]
    entry["origin"] = "third_party"
    entry["status"] = "verified"

    errors = validate_inventory(report, tmp_path, ["README.md"])

    assert "SRC-001 verified third-party material requires source_uri" in errors


def test_patterns_and_local_evidence_cannot_escape_repository(tmp_path: Path):
    report = inventory()
    entry = report["current_entries"][0]
    entry["patterns"] = ["../README.md"]
    entry["evidence"][0]["uri"] = "../NOTICE"

    errors = validate_inventory(report, tmp_path, ["README.md"])

    assert "SRC-001 pattern must be repository-relative: ../README.md" in errors
    assert "SRC-001 evidence 1 path escapes repository root: ../NOTICE" in errors
