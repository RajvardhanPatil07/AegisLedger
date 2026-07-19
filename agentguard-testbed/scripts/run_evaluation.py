#!/usr/bin/env python3
"""End-to-end evaluation entry point: runs the full matrix and writes
docs/RESULTS.md + docs/results.json."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentwallet.eval.harness import run_attack_matrix, run_utility_matrix, write_results

if __name__ == "__main__":
    outdir = Path(__file__).resolve().parent.parent / "docs"
    print("running attack matrix (5 defenses x classes I-III, 3 configs x class IV)...")
    attack_rows = run_attack_matrix()
    print("running task-utility suite...")
    utility_rows = run_utility_matrix()
    write_results(attack_rows, utility_rows, outdir)
    print(f"\nwrote {outdir / 'RESULTS.md'} and results.json\n")
    for r in attack_rows:
        print(
            f"{r['attack']:32s} {r['defense']:20s} "
            f"success={r['success_rate']:.2f} loss/run=${r['avg_loss_usdc']:8.2f} "
            f"detected={r['detection_rate']:.2f}"
        )
    print()
    for r in utility_rows:
        print(
            f"{r['mode']:15s} {r['task']:26s} utility={r['utility']:.2f} "
            f"({r['completed']}/{r['attempted']}) spent=${r['spent_usdc']}"
        )
