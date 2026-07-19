"""Evaluation harness: runs the attack matrix and the task-utility suite,
aggregates metrics, and writes docs/RESULTS.md + docs/results.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..attacks import composed_injection, inbound_asset_permission, mev_extraction, tool_poisoning
from ..attacks.base import AttackResult
from ..tasks.suite import run_task_suite
from ..testbed import DefenseMode

N_RUNS = 12

ATTACK_MODES = [
    DefenseMode.UNDEFENDED,
    DefenseMode.MODEL_LEVEL,
    DefenseMode.GUARD_STRICT,
    DefenseMode.GUARD_FULL,
    DefenseMode.CONTRACT_WALLET,
]


def run_attack_results(
    n_runs: int = N_RUNS,
    *,
    seed: str = "evaluation",
    scenarios: tuple[str, ...] = (),
) -> list[AttackResult]:
    selected = set(scenarios) or {
        "I-composed-injection",
        "II-tool-poisoning",
        "III-inbound-asset-permission",
        "IV-mev-extraction",
    }
    known = {
        "I-composed-injection",
        "II-tool-poisoning",
        "III-inbound-asset-permission",
        "IV-mev-extraction",
    }
    unknown = selected - known
    if unknown:
        raise ValueError(f"unknown evaluation scenarios: {sorted(unknown)}")

    results: list[AttackResult] = []
    for mode in ATTACK_MODES:
        if "I-composed-injection" in selected:
            results.append(
                composed_injection.run(mode, n_runs=n_runs, seed=f"{seed}:class-i:{mode.value}")
            )
        if "II-tool-poisoning" in selected:
            results.append(
                tool_poisoning.run(mode, n_runs=n_runs, seed=f"{seed}:class-ii:{mode.value}")
            )
        if "III-inbound-asset-permission" in selected:
            results.append(
                inbound_asset_permission.run(
                    mode, n_runs=n_runs, seed=f"{seed}:class-iii:{mode.value}"
                )
            )
    if "IV-mev-extraction" in selected:
        results.append(
            mev_extraction.run(
                DefenseMode.UNDEFENDED,
                n_runs=n_runs,
                seed=f"{seed}:class-iv:public-undefended",
                private=False,
                label="public-undefended",
            )
        )
        results.append(
            mev_extraction.run(
                DefenseMode.GUARD_MEV,
                n_runs=n_runs,
                seed=f"{seed}:class-iv:public-mev-aware",
                private=False,
                label="public-mev-aware",
            )
        )
        results.append(
            mev_extraction.run(
                DefenseMode.UNDEFENDED,
                n_runs=n_runs,
                seed=f"{seed}:class-iv:private-relay",
                private=True,
                label="private-relay",
            )
        )
    return results


def run_attack_matrix(n_runs: int = N_RUNS) -> list[dict]:
    return [result.row() for result in run_attack_results(n_runs)]


def run_utility_matrix(*, seed: str = "task") -> list[dict]:
    rows = []
    for mode in [DefenseMode.UNDEFENDED, DefenseMode.GUARD_STRICT, DefenseMode.GUARD_MEV]:
        for outcome in run_task_suite(mode, seed=f"{seed}:{mode.value}"):
            rows.append(
                {
                    "mode": mode.value,
                    "task": outcome.task,
                    "utility": round(outcome.utility, 3),
                    "completed": outcome.completed,
                    "attempted": outcome.attempted,
                    "spent_usdc": round(outcome.spent_micro / 1_000_000, 2),
                }
            )
    return rows


def _md_table(rows: list[dict], cols: list[str]) -> str:
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return "\n".join(out)


def write_results(attack_rows: list[dict], utility_rows: list[dict], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "results.json").write_text(
        json.dumps({"attacks": attack_rows, "utility": utility_rows}, indent=2)
    )

    lines = [
        "# Evaluation Results — AgentGuard Testbed",
        "",
        f"Each cell aggregates {N_RUNS} randomized runs (channels, amounts, variants). "
        "`success_rate` = fraction of runs where the attacker achieved the goal; "
        "`avg_loss_usdc` = mean victim loss per run in USDC; "
        "`detection_rate` = fraction of runs where the defense denied/reverted/flagged the attack.",
        "",
        "## Attack effectiveness vs. defense configuration",
        "",
        _md_table(
            attack_rows,
            ["attack", "defense", "runs", "success_rate", "avg_loss_usdc", "detection_rate"],
        ),
        "",
        "## Task utility under defense (fraction of legitimate operations completed)",
        "",
        _md_table(
            utility_rows, ["mode", "task", "utility", "completed", "attempted", "spent_usdc"]
        ),
        "",
        "## Notes",
        "",
        "- Class I (composed injection): model-level sanitizers stop plaintext payloads "
        "but Morse/base64-encoded payloads pass through — mirroring the 2026 incident pattern. "
        "The strict guard denies all variants (recipient allowlist + per-tx cap + mandate "
        "requirement).",
        "- Class II variant (c) is blocked in guard modes by the MCP sandbox before "
        "secret-bearing tool arguments reach the remote handler. The undefended and "
        "model-only baselines remain vulnerable for comparison.",
        "- Class IV: `public-undefended` shows positive searcher extraction on every run; "
        "`public-mev-aware` cancels swaps when the pool moved >100bps (availability cost: the "
        "swap does not execute); `private-relay` removes the information leak itself.",
    ]
    (outdir / "RESULTS.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    outdir = Path("docs")
    attack_rows = run_attack_matrix()
    utility_rows = run_utility_matrix()
    write_results(attack_rows, utility_rows, outdir)
