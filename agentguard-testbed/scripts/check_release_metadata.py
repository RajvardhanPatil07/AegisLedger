#!/usr/bin/env python3
"""Fail closed when AegisLedger release metadata disagrees."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import yaml

Mode = Literal["auto", "candidate", "prepared", "release"]


def collect_versions(repository_root: Path) -> dict[str, str]:
    """Return every independently declared AegisLedger version."""
    project_root = repository_root / "agentguard-testbed"
    python_project = _read_toml(project_root / "pyproject.toml")
    signer_project = _read_toml(project_root / "signer" / "Cargo.toml")
    web_project = json.loads((project_root / "web" / "package.json").read_text(encoding="utf-8"))
    citation = _read_yaml(repository_root / "CITATION.cff")
    runtime_text = (project_root / "src" / "aegisledger" / "__init__.py").read_text(
        encoding="utf-8"
    )
    runtime_match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']$', runtime_text, re.M)
    if runtime_match is None:
        raise ValueError("Python runtime __version__ declaration is missing")
    return {
        "citation": str(citation["version"]),
        "python-package": str(python_project["project"]["version"]),
        "python-runtime": runtime_match.group(1),
        "rust-signer": str(signer_project["package"]["version"]),
        "web-console": str(web_project["version"]),
    }


def validate_metadata(
    repository_root: Path,
    *,
    mode: Mode,
    tags: Sequence[str],
) -> list[str]:
    """Return all metadata-policy errors across the candidate-to-release lifecycle."""
    if mode not in {"auto", "candidate", "prepared", "release"}:
        raise ValueError(f"unsupported release metadata mode: {mode}")

    versions = collect_versions(repository_root)
    version = versions["python-package"]
    errors: list[str] = []
    if len(set(versions.values())) != 1:
        details = ", ".join(f"{name}={value}" for name, value in sorted(versions.items()))
        errors.append(f"version mismatch: {details}")

    citation = _read_yaml(repository_root / "CITATION.cff")
    citation_date = citation.get("date-released")
    changelog = (repository_root / "CHANGELOG.md").read_text(encoding="utf-8")
    roadmap = (repository_root / "ROADMAP.md").read_text(encoding="utf-8")

    if mode == "auto":
        if citation_date is None:
            mode = "candidate"
        elif f"v{version}" in tags:
            mode = "release"
        else:
            mode = "prepared"

    if mode == "candidate":
        if citation_date is not None:
            errors.append("candidate metadata must not set CITATION.cff date-released")
        if not re.search(r"^## \[Unreleased\]\s*$", changelog, re.M):
            errors.append("candidate changelog must retain an [Unreleased] section")
        if not re.search(
            rf"^## Current candidate: {re.escape(version)}\s*$",
            roadmap,
            re.M,
        ):
            errors.append(f"ROADMAP.md must declare Current candidate: {version}")
        if f"v{version}" in tags:
            errors.append(f"candidate version already has release tag v{version}")
        return errors

    if citation_date is None:
        errors.append("release metadata must set CITATION.cff date-released")
        release_date = None
    else:
        release_date = str(citation_date)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", release_date) is None:
            errors.append("CITATION.cff date-released must use YYYY-MM-DD")

    if not re.search(
        rf"^## Current release: {re.escape(version)}\s*$",
        roadmap,
        re.M,
    ):
        errors.append(f"ROADMAP.md must declare Current release: {version}")
    changelog_match = re.search(
        rf"^## \[{re.escape(version)}\] - (\d{{4}}-\d{{2}}-\d{{2}})\s*$",
        changelog,
        re.M,
    )
    if changelog_match is None:
        errors.append(f"CHANGELOG.md must contain a dated [{version}] release section")
    elif release_date is not None and changelog_match.group(1) != release_date:
        errors.append("CHANGELOG.md release date must match CITATION.cff date-released")
    if mode == "prepared" and f"v{version}" in tags:
        errors.append(f"prepared release already has tag v{version}")
    elif mode == "release" and f"v{version}" not in tags:
        errors.append(f"release tag v{version} is missing")
    return errors


def _read_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _read_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML object")
    return value


def _git_tags(repository_root: Path) -> tuple[str, ...]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to validate release tags")
    result = subprocess.run(  # noqa: S603 - fixed git command; no untrusted arguments
        [git, "tag", "--list"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return tuple(line for line in result.stdout.splitlines() if line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("auto", "candidate", "prepared", "release"),
        default="auto",
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repository_root = args.repository_root.resolve()
    versions = collect_versions(repository_root)
    errors = validate_metadata(
        repository_root,
        mode=args.mode,
        tags=_git_tags(repository_root),
    )
    print(", ".join(f"{name}={value}" for name, value in sorted(versions.items())))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"Release metadata is consistent for {args.mode} mode.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
