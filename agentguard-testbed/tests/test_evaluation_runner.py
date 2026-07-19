import json

import pytest

from aegisledger.evaluation import (
    ExperimentRunner,
    create_experiment_spec,
    wilson_interval,
)


def test_wilson_interval_is_bounded_and_contains_observed_rate():
    low, high = wilson_interval(7, 10)
    assert 0.0 <= low <= 0.7 <= high <= 1.0
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_runner_retains_manifest_raw_logs_and_reproducible_outcomes(tmp_path):
    spec = create_experiment_spec(
        seed="reproducible-seed",
        runs_per_scenario=3,
        scenarios=("II-tool-poisoning",),
        commit_sha="a" * 40,
    )
    first = ExperimentRunner().run(spec, tmp_path / "first")
    second = ExperimentRunner().run(spec, tmp_path / "second")

    assert first.summary["configuration_hash"] == spec.configuration_hash
    assert first.summary["raw_run_count"] == 15
    assert first.summary["attack_metrics"] == second.summary["attack_metrics"]
    assert first.raw_runs == second.raw_runs

    manifest = json.loads((tmp_path / "first" / "manifest.json").read_text())
    summary = json.loads((tmp_path / "first" / "summary.json").read_text())
    raw_lines = (tmp_path / "first" / "raw_runs.jsonl").read_text().splitlines()
    assert manifest["commit_sha"] == "a" * 40
    assert summary["raw_run_count"] == len(raw_lines)
    assert all("run_seed" in json.loads(line) for line in raw_lines)

    recovered = ExperimentRunner().run(spec, tmp_path / "first")
    assert recovered.summary == first.summary
    assert recovered.raw_runs == first.raw_runs


def test_runner_fails_closed_on_partial_recovery_directory(tmp_path):
    spec = create_experiment_spec(
        seed="partial-recovery",
        runs_per_scenario=1,
        scenarios=("II-tool-poisoning",),
        commit_sha="c" * 40,
    )
    output = tmp_path / "partial"
    output.mkdir()
    (output / "manifest.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="incomplete"):
        ExperimentRunner().run(spec, output)


def test_guard_tool_sandbox_closes_exfiltration_in_evaluation(tmp_path):
    spec = create_experiment_spec(
        seed="dlp-gate",
        runs_per_scenario=6,
        scenarios=("II-tool-poisoning",),
        commit_sha="b" * 40,
    )
    artifacts = ExperimentRunner().run(spec, tmp_path / "experiment")
    strict = next(
        row for row in artifacts.summary["attack_metrics"] if row["defense"] == "guard_strict"
    )
    assert strict["success_rate"] == 0.0
    assert strict["detection_rate"] == 1.0
