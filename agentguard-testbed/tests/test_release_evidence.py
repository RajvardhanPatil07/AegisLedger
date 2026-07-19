from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.release_evidence import build_manifest, validate_manifest

COMMIT = "a" * 40


def test_manifest_binds_sorted_artifacts_to_commit_and_checksums(tmp_path: Path):
    evidence = tmp_path / "artifacts" / "candidate"
    evidence.mkdir(parents=True)
    (evidence / "z.log").write_text("last\n", encoding="utf-8")
    (evidence / "a.json").write_text('{"passed": true}\n', encoding="utf-8")

    manifest = build_manifest(
        tmp_path,
        [evidence],
        artifact_root=evidence,
        candidate_commit=COMMIT,
        generated_at=datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
    )

    assert manifest["schema_version"] == "aegisledger.release_evidence.v1"
    assert manifest["candidate_commit"] == COMMIT
    assert manifest["artifact_root"] == "artifacts/candidate"
    assert [item["path"] for item in manifest["artifacts"]] == [
        "a.json",
        "z.log",
    ]
    assert all(len(item["sha256"]) == 64 for item in manifest["artifacts"])
    assert validate_manifest(manifest, tmp_path, expected_commit=COMMIT) == []

    downloaded = tmp_path / "downloaded"
    downloaded.mkdir()
    (downloaded / "a.json").write_text('{"passed": true}\n', encoding="utf-8")
    (downloaded / "z.log").write_text("last\n", encoding="utf-8")
    assert validate_manifest(
        manifest,
        tmp_path,
        expected_commit=COMMIT,
        artifact_root=downloaded,
    ) == []


def test_manifest_validation_detects_tampering_and_missing_files(tmp_path: Path):
    artifact = tmp_path / "runtime.json"
    artifact.write_text('{"passed": true}\n', encoding="utf-8")
    manifest = build_manifest(
        tmp_path,
        [artifact],
        candidate_commit=COMMIT,
        generated_at=datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
    )

    artifact.write_text('{"passed": false}\n', encoding="utf-8")
    errors = validate_manifest(manifest, tmp_path, expected_commit=COMMIT)
    assert "runtime.json size does not match manifest" in errors
    assert "runtime.json sha256 does not match manifest" in errors

    artifact.unlink()
    errors = validate_manifest(manifest, tmp_path, expected_commit=COMMIT)
    assert "artifact is missing: runtime.json" in errors


def test_manifest_validation_rejects_commit_mismatch(tmp_path: Path):
    artifact = tmp_path / "report.xml"
    artifact.write_text("<testsuite/>\n", encoding="utf-8")
    manifest = build_manifest(
        tmp_path,
        [artifact],
        candidate_commit=COMMIT,
        generated_at=datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
    )

    errors = validate_manifest(manifest, tmp_path, expected_commit="b" * 40)

    assert (
        f"candidate_commit {COMMIT} does not match expected commit " + ("b" * 40)
    ) in errors


def test_build_rejects_duplicate_or_outside_artifacts(tmp_path: Path):
    artifact = tmp_path / "report.txt"
    artifact.write_text("passed\n", encoding="utf-8")
    generated_at = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

    with pytest.raises(ValueError, match="duplicate artifact"):
        build_manifest(
            tmp_path,
            [artifact, artifact],
            candidate_commit=COMMIT,
            generated_at=generated_at,
        )

    outside = tmp_path.parent / "outside-report.txt"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        with pytest.raises(ValueError, match="outside repository root"):
            build_manifest(
                tmp_path,
                [outside],
                candidate_commit=COMMIT,
                generated_at=generated_at,
            )
    finally:
        outside.unlink()


def test_schema_rejects_unsafe_paths_and_malformed_commit(tmp_path: Path):
    artifact = tmp_path / "report.txt"
    artifact.write_text("passed\n", encoding="utf-8")
    manifest = build_manifest(
        tmp_path,
        [artifact],
        candidate_commit=COMMIT,
        generated_at=datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
    )
    manifest["candidate_commit"] = "deadbeef"
    manifest["artifacts"][0]["path"] = "../report.txt"

    errors = validate_manifest(manifest, tmp_path, expected_commit=COMMIT)

    assert "candidate_commit must be a lowercase 40-character Git SHA" in errors
    assert "artifact 1 path must be repository-relative" in errors
