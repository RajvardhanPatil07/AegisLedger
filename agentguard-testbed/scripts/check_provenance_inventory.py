#!/usr/bin/env python3
"""Validate provenance coverage and public-release clearance for tracked material."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from collections.abc import Callable
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

SCHEMA_VERSION = "aegisledger.provenance.v1"
ORIGINS = {
    "repository_authored",
    "third_party",
    "generated",
    "external_reference",
}
STATUSES = {"verified", "owner_confirmation_required", "excluded"}
HistoryObjectExists = Callable[[str, str], bool]


def validate_inventory(
    inventory: dict[str, Any],
    repository_root: Path,
    tracked_files: list[str],
    *,
    history_object_exists: HistoryObjectExists | None = None,
) -> list[str]:
    """Return schema, attribution, evidence, and tracked-file coverage errors."""
    errors: list[str] = []
    if inventory.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    for field in ("owner", "last_reviewed"):
        if not isinstance(inventory.get(field), str) or not inventory[field].strip():
            errors.append(f"{field} must be a non-empty string")
    _validate_date(inventory.get("last_reviewed"), "last_reviewed", errors)

    current_entries = inventory.get("current_entries")
    history_entries = inventory.get("history_entries")
    if not isinstance(current_entries, list) or not current_entries:
        errors.append("current_entries must be a non-empty array")
        current_entries = []
    if not isinstance(history_entries, list):
        errors.append("history_entries must be an array")
        history_entries = []

    seen_ids: set[str] = set()
    patterns: list[tuple[str, str]] = []
    for index, entry in enumerate(current_entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"current entry {index} must be an object")
            continue
        entry_id = _entry_label(entry, f"current[{index}]")
        _validate_entry_common(entry, entry_id, repository_root, seen_ids, errors)
        if re.fullmatch(r"SRC-\d{3}", entry_id) is None:
            errors.append(f"{entry_id} id must match SRC-NNN")
        entry_patterns = entry.get("patterns")
        if not isinstance(entry_patterns, list) or not entry_patterns:
            errors.append(f"{entry_id} patterns must be a non-empty array")
            continue
        for pattern in entry_patterns:
            if not isinstance(pattern, str) or not pattern:
                errors.append(f"{entry_id} patterns must contain non-empty strings")
            elif not _is_repository_relative(pattern):
                errors.append(f"{entry_id} pattern must be repository-relative: {pattern}")
            else:
                patterns.append((entry_id, pattern))

    for index, entry in enumerate(history_entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"history entry {index} must be an object")
            continue
        entry_id = _entry_label(entry, f"history[{index}]")
        _validate_entry_common(entry, entry_id, repository_root, seen_ids, errors)
        if re.fullmatch(r"HIST-\d{3}", entry_id) is None:
            errors.append(f"{entry_id} id must match HIST-NNN")
        history_path = entry.get("path")
        valid_history_path = isinstance(history_path, str) and _is_repository_relative(
            history_path
        )
        if not valid_history_path:
            errors.append(f"{entry_id} path must be repository-relative")
        introduced_commit = entry.get("introduced_commit")
        valid_commit = isinstance(introduced_commit, str) and re.fullmatch(
            r"[0-9a-f]{40}", introduced_commit
        ) is not None
        if not valid_commit:
            errors.append(
                f"{entry_id} introduced_commit must be a lowercase 40-character Git SHA"
            )
        if (
            history_object_exists is not None
            and valid_history_path
            and valid_commit
            and isinstance(introduced_commit, str)
            and isinstance(history_path, str)
            and not history_object_exists(introduced_commit, history_path)
        ):
            errors.append(
                f"{entry_id} historical object is not present: "
                f"{introduced_commit}:{history_path}"
            )

    for tracked_file in tracked_files:
        normalized = PurePosixPath(tracked_file).as_posix()
        matching_entries = sorted(
            {entry_id for entry_id, pattern in patterns if fnmatchcase(normalized, pattern)}
        )
        if not matching_entries:
            errors.append(f"tracked file is missing provenance coverage: {normalized}")
        elif len(matching_entries) > 1:
            errors.append(
                f"tracked file has ambiguous provenance coverage: {normalized} "
                f"({', '.join(matching_entries)})"
            )
    return errors


def _validate_entry_common(
    entry: dict[str, Any],
    entry_id: str,
    repository_root: Path,
    seen_ids: set[str],
    errors: list[str],
) -> None:
    if entry_id in seen_ids:
        errors.append(f"duplicate provenance id {entry_id}")
    seen_ids.add(entry_id)
    for field in ("title", "copyright_holder", "license"):
        if not isinstance(entry.get(field), str) or not entry[field].strip():
            errors.append(f"{entry_id} {field} must be a non-empty string")

    origin = entry.get("origin")
    if origin not in ORIGINS:
        errors.append(f"{entry_id} origin {origin!r} is unsupported")
    status = entry.get("status")
    if status not in STATUSES:
        errors.append(f"{entry_id} status {status!r} is unsupported")
    if status == "excluded" and (
        not isinstance(entry.get("exclusion_reason"), str)
        or not entry["exclusion_reason"].strip()
    ):
        errors.append(f"{entry_id} excluded status requires exclusion_reason")
    if origin == "third_party" and status == "verified":
        source_uri = entry.get("source_uri")
        if not isinstance(source_uri, str) or not urlparse(source_uri).scheme:
            errors.append(f"{entry_id} verified third-party material requires source_uri")

    evidence = entry.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{entry_id} evidence must be a non-empty array")
        return
    for index, item in enumerate(evidence, start=1):
        item_label = f"{entry_id} evidence {index}"
        if not isinstance(item, dict):
            errors.append(f"{item_label} must be an object")
            continue
        if not isinstance(item.get("label"), str) or not item["label"].strip():
            errors.append(f"{item_label} label must be a non-empty string")
        uri = item.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            errors.append(f"{item_label} uri must be a non-empty string")
        else:
            _validate_evidence_uri(uri, item_label, repository_root, errors)


def _entry_label(entry: dict[str, Any], fallback: str) -> str:
    entry_id = entry.get("id")
    return entry_id if isinstance(entry_id, str) and entry_id else fallback


def _is_repository_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value not in {"", "."}


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


def _validate_date(value: object, label: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        return
    try:
        date.fromisoformat(value)
    except ValueError:
        errors.append(f"{label} must use YYYY-MM-DD")


def release_readiness(
    inventory: dict[str, Any],
    repository_root: Path,
    tracked_files: list[str],
    *,
    history_object_exists: HistoryObjectExists | None = None,
) -> tuple[bool, list[str]]:
    """Return whether every distributable current and historical entry is cleared."""
    errors = validate_inventory(
        inventory,
        repository_root,
        tracked_files,
        history_object_exists=history_object_exists,
    )
    if errors:
        return False, errors
    reasons: list[str] = []
    for entry in [*inventory["current_entries"], *inventory["history_entries"]]:
        if entry["status"] == "owner_confirmation_required":
            reasons.append(f"{entry['id']} requires owner confirmation")
    return not reasons, reasons


def git_tracked_files(repository_root: Path) -> list[str]:
    """Return the current Git index as normalized repository-relative paths."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to enumerate tracked files")
    result = subprocess.run(  # noqa: S603 - fixed Git command; no untrusted arguments
        [git, "-C", str(repository_root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def git_history_object_checker(repository_root: Path) -> HistoryObjectExists:
    """Build a checker for exact commit:path objects in the local Git history."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to verify historical provenance")

    def object_exists(commit: str, path: str) -> bool:
        result = subprocess.run(  # noqa: S603 - fixed Git command; validated object ID/path
            [git, "-C", str(repository_root), "cat-file", "-e", f"{commit}:{path}"],
            check=False,
            capture_output=True,
        )
        return result.returncode == 0

    return object_exists


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--require-release-ready", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repository_root = args.repository_root.resolve()
    inventory_path = args.inventory or (
        repository_root / "agentguard-testbed" / "docs" / "provenance.json"
    )
    value = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("provenance inventory must be a JSON object")
    tracked_files = git_tracked_files(repository_root)
    history_object_exists = git_history_object_checker(repository_root)
    if args.require_release_ready:
        passed, messages = release_readiness(
            value,
            repository_root,
            tracked_files,
            history_object_exists=history_object_exists,
        )
    else:
        messages = validate_inventory(
            value,
            repository_root,
            tracked_files,
            history_object_exists=history_object_exists,
        )
        passed = not messages
    for message in messages:
        print(f"ERROR: {message}")
    if passed:
        suffix = " and release-cleared" if args.require_release_ready else ""
        print(f"Provenance inventory is valid{suffix}.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
