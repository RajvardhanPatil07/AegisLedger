#!/usr/bin/env python3
"""Build and verify checksum manifests for exact-commit release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = "aegisledger.release_evidence.v1"


def build_manifest(
    repository_root: Path,
    artifact_paths: list[Path],
    *,
    artifact_root: Path | None = None,
    candidate_commit: str,
    generated_at: datetime,
) -> dict[str, Any]:
    """Build a deterministic file inventory around one commit and generation time."""
    if re.fullmatch(r"[0-9a-f]{40}", candidate_commit) is None:
        raise ValueError("candidate_commit must be a lowercase 40-character Git SHA")
    if generated_at.utcoffset() is None:
        raise ValueError("generated_at must include a timezone")
    repository_root = repository_root.resolve()
    artifact_root = (artifact_root or repository_root).resolve()
    if not artifact_root.is_relative_to(repository_root):
        raise ValueError("artifact_root must be inside repository root")
    files = _expand_artifacts(repository_root, artifact_root, artifact_paths)
    artifacts = [
        {
            "path": path.relative_to(artifact_root).as_posix(),
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in files
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_commit": candidate_commit,
        "generated_at": generated_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "artifact_root": _relative_root(repository_root, artifact_root),
        "artifacts": artifacts,
    }


def _relative_root(repository_root: Path, artifact_root: Path) -> str:
    relative = artifact_root.relative_to(repository_root).as_posix()
    return relative or "."


def _expand_artifacts(
    repository_root: Path,
    artifact_root: Path,
    artifact_paths: list[Path],
) -> list[Path]:
    if not artifact_paths:
        raise ValueError("at least one artifact path is required")
    root = repository_root.resolve()
    files: list[Path] = []
    seen: set[Path] = set()
    for supplied in artifact_paths:
        resolved = supplied.resolve()
        if not resolved.is_relative_to(root):
            raise ValueError(f"artifact is outside repository root: {supplied}")
        if not resolved.is_relative_to(artifact_root):
            raise ValueError(f"artifact is outside artifact_root: {supplied}")
        candidates = (
            sorted(path.resolve() for path in resolved.rglob("*") if path.is_file())
            if resolved.is_dir()
            else [resolved]
        )
        if not candidates:
            raise ValueError(f"artifact path contains no files: {supplied}")
        for candidate in candidates:
            if not candidate.is_relative_to(root):
                raise ValueError(f"artifact is outside repository root: {candidate}")
            if not candidate.is_relative_to(artifact_root):
                raise ValueError(f"artifact is outside artifact_root: {candidate}")
            if not candidate.is_file():
                raise ValueError(f"artifact is not a regular file: {candidate}")
            if candidate in seen:
                raise ValueError(f"duplicate artifact: {candidate}")
            seen.add(candidate)
            files.append(candidate)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_manifest(
    manifest: dict[str, Any],
    repository_root: Path,
    *,
    expected_commit: str,
    artifact_root: Path | None = None,
) -> list[str]:
    """Return schema, commit-binding, path-safety, and checksum errors."""
    errors: list[str] = []
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")

    candidate_commit = manifest.get("candidate_commit")
    if not isinstance(candidate_commit, str) or re.fullmatch(
        r"[0-9a-f]{40}", candidate_commit
    ) is None:
        errors.append("candidate_commit must be a lowercase 40-character Git SHA")
    elif candidate_commit != expected_commit:
        errors.append(
            f"candidate_commit {candidate_commit} does not match expected commit "
            f"{expected_commit}"
        )

    generated_at = manifest.get("generated_at")
    if not isinstance(generated_at, str) or not _is_timezone_aware_datetime(generated_at):
        errors.append("generated_at must be a timezone-aware ISO 8601 timestamp")

    recorded_root = manifest.get("artifact_root")
    if not isinstance(recorded_root, str) or not _is_repository_relative_root(
        recorded_root
    ):
        errors.append("artifact_root must be repository-relative")
        evidence_root = repository_root.resolve()
    elif artifact_root is None:
        evidence_root = (repository_root.resolve() / recorded_root).resolve()
        if not evidence_root.is_relative_to(repository_root.resolve()):
            errors.append("artifact_root resolves outside repository root")
    else:
        evidence_root = artifact_root.resolve()

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return [*errors, "artifacts must be a non-empty array"]
    seen_paths: set[str] = set()
    for index, item in enumerate(artifacts, start=1):
        label = f"artifact {index}"
        if not isinstance(item, dict):
            errors.append(f"{label} must be an object")
            continue
        raw_path = item.get("path")
        if not isinstance(raw_path, str) or not _is_repository_relative(raw_path):
            errors.append(f"{label} path must be repository-relative")
            continue
        if raw_path in seen_paths:
            errors.append(f"duplicate artifact path: {raw_path}")
        seen_paths.add(raw_path)
        expected_sha = item.get("sha256")
        if not isinstance(expected_sha, str) or re.fullmatch(
            r"[0-9a-f]{64}", expected_sha
        ) is None:
            errors.append(f"{raw_path} sha256 must be 64 lowercase hexadecimal characters")
            expected_sha = None
        expected_size = item.get("size_bytes")
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
        ):
            errors.append(f"{raw_path} size_bytes must be a non-negative integer")
            expected_size = None

        candidate = (evidence_root / raw_path).resolve()
        if not candidate.is_relative_to(evidence_root):
            errors.append(f"{raw_path} resolves outside artifact root")
        elif not candidate.is_file():
            errors.append(f"artifact is missing: {raw_path}")
        else:
            if expected_size is not None and candidate.stat().st_size != expected_size:
                errors.append(f"{raw_path} size does not match manifest")
            if expected_sha is not None and _sha256(candidate) != expected_sha:
                errors.append(f"{raw_path} sha256 does not match manifest")
    return errors


def _is_repository_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value not in {"", "."}


def _is_repository_relative_root(value: str) -> bool:
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and bool(value)


def _is_timezone_aware_datetime(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.utcoffset() is not None


def git_commit(repository_root: Path) -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to bind release evidence")
    result = subprocess.run(  # noqa: S603 - fixed Git command; no untrusted arguments
        [git, "-C", str(repository_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip().lower()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RuntimeError("git returned an invalid commit SHA")
    return commit


def git_is_clean(repository_root: Path) -> bool:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to verify release evidence")
    result = subprocess.run(  # noqa: S603 - fixed Git command; no untrusted arguments
        [git, "-C", str(repository_root), "status", "--porcelain", "--untracked-files=all"],
        check=True,
        capture_output=True,
    )
    return not result.stdout


def _repository_path(repository_root: Path, value: Path) -> Path:
    return value if value.is_absolute() else repository_root / value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="create a new evidence manifest")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--artifact", type=Path, action="append", required=True)

    verify = subparsers.add_parser("verify", help="verify an existing evidence manifest")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--artifact-root", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repository_root = args.repository_root.resolve()
    commit = git_commit(repository_root)
    if args.command == "build":
        if not git_is_clean(repository_root):
            print("ERROR: repository must be clean before evidence is generated")
            return 1
        output = _repository_path(repository_root, args.output).resolve()
        if not output.is_relative_to(repository_root):
            print("ERROR: manifest output must be inside the repository")
            return 1
        artifacts = [
            _repository_path(repository_root, artifact) for artifact in args.artifact
        ]
        manifest = build_manifest(
            repository_root,
            artifacts,
            artifact_root=output.parent,
            candidate_commit=commit,
            generated_at=datetime.now(UTC),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"Wrote exact-commit evidence manifest: {output}")
        return 0

    manifest_path = _repository_path(repository_root, args.manifest).resolve()
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("release evidence manifest must be a JSON object")
    artifact_root = (
        _repository_path(repository_root, args.artifact_root)
        if args.artifact_root is not None
        else None
    )
    errors = validate_manifest(
        value,
        repository_root,
        expected_commit=commit,
        artifact_root=artifact_root,
    )
    for error in errors:
        print(f"ERROR: {error}")
    if not errors:
        print(f"Release evidence is complete and bound to {commit}.")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
