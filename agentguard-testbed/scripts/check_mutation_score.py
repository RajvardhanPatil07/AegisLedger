#!/usr/bin/env python3
"""Enforce a minimum score for a mutmut CI/CD statistics report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

UNRESOLVED_FIELDS = (
    "no_tests",
    "skipped",
    "suspicious",
    "timeout",
    "check_was_interrupted_by_user",
    "segfault",
)


def evaluate(stats: dict[str, Any], minimum_score: float) -> tuple[bool, str]:
    """Return whether assessed mutants meet the score and completeness policy."""
    if not 0 <= minimum_score <= 100:
        raise ValueError("Minimum mutation score must be between 0 and 100.")

    killed = _nonnegative_integer(stats, "killed")
    survived = _nonnegative_integer(stats, "survived")
    unresolved = {field: _nonnegative_integer(stats, field) for field in UNRESOLVED_FIELDS}
    assessed = killed + survived

    if assessed == 0:
        return False, "Mutation report contains no assessed mutants."

    unresolved_total = sum(unresolved.values())
    if unresolved_total:
        details = ", ".join(f"{key}={value}" for key, value in unresolved.items() if value)
        return False, f"Mutation run has unresolved results: {details}."

    score = killed * 100 / assessed
    message = (
        f"Mutation score {score:.2f}% ({killed} killed / {assessed} assessed); "
        f"minimum {minimum_score:.2f}%."
    )
    return score >= minimum_score, message


def _nonnegative_integer(stats: dict[str, Any], field: str) -> int:
    value = stats.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"Mutation report field {field!r} must be a non-negative integer.")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="mutmut-cicd-stats.json path")
    parser.add_argument("--minimum-score", type=float, default=95.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    stats = json.loads(args.report.read_text(encoding="utf-8"))
    if not isinstance(stats, dict):
        raise ValueError("Mutation report must be a JSON object.")
    passed, message = evaluate(stats, args.minimum_score)
    print(message)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
