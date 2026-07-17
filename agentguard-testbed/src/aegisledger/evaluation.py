"""Reproducible experiment manifests, raw logs, statistics, and CLI execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, StringConstraints, field_validator

from agentwallet.chain.crypto import KeyPair
from agentwallet.eval.harness import run_attack_results, run_utility_matrix

from .canonical import canonical_json, uuid7
from .contracts import StrictModel

Scenario = Literal[
    "I-composed-injection",
    "II-tool-poisoning",
    "III-inbound-asset-permission",
    "IV-mev-extraction",
]


class ModelMetadataV1(StrictModel):
    provider: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    model: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    parameters_hash: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]


class ExperimentSpecV1(StrictModel):
    model_config = ConfigDict(protected_namespaces=())

    schema_version: Literal["aegisledger.experiment.v1"]
    experiment_id: uuid.UUID = Field(default_factory=uuid7)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    commit_sha: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    configuration_hash: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]
    seed: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    scenarios: tuple[Scenario, ...]
    runs_per_scenario: Annotated[int, Field(gt=0, le=10_000)]
    model_metadata: ModelMetadataV1 | None = None

    @field_validator("experiment_id")
    @classmethod
    def require_uuid7(cls, value: uuid.UUID) -> uuid.UUID:
        if value.version != 7:
            raise ValueError("experiment_id must be UUIDv7")
        return value

    @field_validator("created_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a UTC offset")
        return value.astimezone(UTC)

    @field_validator("scenarios", mode="before")
    @classmethod
    def accept_scenario_array(cls, value: object) -> tuple[object, ...]:
        if not isinstance(value, (list, tuple)):
            raise TypeError("scenarios must be an array")
        return tuple(value)


def create_experiment_spec(
    *,
    seed: str,
    runs_per_scenario: int,
    scenarios: tuple[Scenario, ...] = (),
    commit_sha: str,
    model_metadata: ModelMetadataV1 | None = None,
) -> ExperimentSpecV1:
    selected: tuple[Scenario, ...] = scenarios or (
        "I-composed-injection",
        "II-tool-poisoning",
        "III-inbound-asset-permission",
        "IV-mev-extraction",
    )
    configuration = {
        "schema_version": "aegisledger.experiment_configuration.v1",
        "seed": seed,
        "runs_per_scenario": runs_per_scenario,
        "scenarios": list(selected),
        "model_metadata": (
            model_metadata.model_dump(mode="json") if model_metadata is not None else None
        ),
    }
    configuration_hash = "0x" + hashlib.sha256(canonical_json(configuration)).hexdigest()
    return ExperimentSpecV1(
        schema_version="aegisledger.experiment.v1",
        commit_sha=commit_sha,
        configuration_hash=configuration_hash,
        seed=seed,
        scenarios=selected,
        runs_per_scenario=runs_per_scenario,
        model_metadata=model_metadata,
    )


def wilson_interval(
    successes: int,
    trials: int,
    *,
    z: float = 1.959963984540054,
) -> tuple[float, float]:
    if trials == 0:
        return 0.0, 1.0
    proportion = successes / trials
    denominator = 1 + z * z / trials
    center = (proportion + z * z / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


@dataclass(frozen=True)
class ExperimentArtifacts:
    spec: ExperimentSpecV1
    summary: dict[str, object]
    raw_runs: tuple[dict[str, object], ...]
    output_directory: Path


class ExperimentRunner:
    def run(self, spec: ExperimentSpecV1, output_directory: Path) -> ExperimentArtifacts:
        started = time.perf_counter_ns()
        attack_results = run_attack_results(
            spec.runs_per_scenario,
            seed=spec.seed,
            scenarios=spec.scenarios,
        )
        utility_rows = run_utility_matrix(seed=spec.seed)

        raw_runs: list[dict[str, object]] = []
        attack_metrics: list[dict[str, object]] = []
        for result in attack_results:
            for index, outcome in enumerate(result.outcomes):
                raw_runs.append(
                    {
                        "schema_version": "aegisledger.raw_run.v1",
                        "experiment_id": str(spec.experiment_id),
                        "attack": result.name,
                        "defense": result.defense,
                        "run_index": index,
                        "run_seed": f"{spec.seed}:{result.name}:{result.defense}:{index}",
                        "attempted": outcome.attempted,
                        "succeeded": outcome.succeeded,
                        "detected": outcome.detected,
                        "loss_base_units": outcome.loss_micro,
                        "attacker_gain_base_units": outcome.attacker_gain_micro,
                        "notes": outcome.notes,
                    }
                )
            successes = sum(outcome.succeeded for outcome in result.outcomes)
            detected = sum(outcome.detected for outcome in result.outcomes)
            success_low, success_high = wilson_interval(successes, len(result.outcomes))
            detection_low, detection_high = wilson_interval(detected, len(result.outcomes))
            attack_metrics.append(
                {
                    **result.row(),
                    "success_rate_ci95": [round(success_low, 4), round(success_high, 4)],
                    "detection_rate_ci95": [round(detection_low, 4), round(detection_high, 4)],
                    "total_loss_base_units": result.total_loss_micro,
                }
            )

        attempted = sum(int(row["attempted"]) for row in utility_rows)
        completed = sum(int(row["completed"]) for row in utility_rows)
        false_positives = attempted - completed
        false_positive_rate = false_positives / max(attempted, 1)
        elapsed_seconds = (time.perf_counter_ns() - started) / 1_000_000_000
        signing_samples = self._measure_signing_overhead()
        summary: dict[str, object] = {
            "schema_version": "aegisledger.experiment_summary.v1",
            "experiment_id": str(spec.experiment_id),
            "commit_sha": spec.commit_sha,
            "configuration_hash": spec.configuration_hash,
            "seed": spec.seed,
            "model_metadata": (
                spec.model_metadata.model_dump(mode="json")
                if spec.model_metadata is not None
                else None
            ),
            "attack_metrics": attack_metrics,
            "utility_metrics": utility_rows,
            "false_positive_rate": round(false_positive_rate, 4),
            "availability_cost": round(1 - completed / max(attempted, 1), 4),
            "raw_run_count": len(raw_runs),
            "performance": {
                "evaluation_duration_ms": round(elapsed_seconds * 1_000, 3),
                "throughput_runs_per_second": round(len(raw_runs) / max(elapsed_seconds, 1e-9), 3),
                "local_signing_p50_ms": round(statistics.median(signing_samples), 4),
                "local_signing_p95_ms": round(_percentile(signing_samples, 0.95), 4),
            },
            "runtime": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
        }

        output_directory.mkdir(parents=True, exist_ok=False)
        _write_json(output_directory / "manifest.json", spec.model_dump(mode="json"))
        _write_json(output_directory / "summary.json", summary)
        (output_directory / "raw_runs.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in raw_runs),
            encoding="utf-8",
        )
        return ExperimentArtifacts(spec, summary, tuple(raw_runs), output_directory)

    @staticmethod
    def _measure_signing_overhead(samples: int = 50) -> list[float]:
        keys = KeyPair.from_seed("evaluation-signing-overhead")
        payload = b"aegisledger-signing-overhead-v1"
        durations: list[float] = []
        for _ in range(samples):
            started = time.perf_counter_ns()
            keys.sign(payload)
            durations.append((time.perf_counter_ns() - started) / 1_000_000)
        return durations


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _current_commit() -> str:
    configured = os.getenv("AEGISLEDGER_COMMIT_SHA")
    if configured:
        return configured.lower()
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required when AEGISLEDGER_COMMIT_SHA is not set")
    result = subprocess.run(  # noqa: S603 - fixed executable resolved from PATH
        [git, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip().lower()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a reproducible AegisLedger experiment")
    parser.add_argument("--seed", default="research-baseline")
    parser.add_argument("--runs", type=int, default=12)
    parser.add_argument("--scenario", action="append", dest="scenarios")
    parser.add_argument("--output-root", type=Path, default=Path("artifacts/experiments"))
    arguments = parser.parse_args()
    spec = create_experiment_spec(
        seed=arguments.seed,
        runs_per_scenario=arguments.runs,
        scenarios=tuple(arguments.scenarios or ()),
        commit_sha=_current_commit(),
    )
    output = arguments.output_root / str(spec.experiment_id)
    ExperimentRunner().run(spec, output)
    print(output)


if __name__ == "__main__":
    main()
