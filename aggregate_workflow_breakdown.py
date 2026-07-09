#!/usr/bin/env python3
from __future__ import annotations

import csv
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "results" / "evaluation_results_all_seeds.csv"
OUTPUT = ROOT / "results" / "workflow_breakdown.csv"


def pct(n: int, d: int) -> float:
    return 0.0 if d == 0 else 100.0 * n / d


def main() -> bool:
    with INPUT.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    configurations = list(dict.fromkeys(r["configuration"] for r in rows))
    workflows = list(dict.fromkeys(r["workflow"] for r in rows))
    fields = [
        "configuration", "workflow", "benign_attempts", "adversarial_attempts",
        "ASR", "TSR", "FDR", "DVR", "mean_latency_ms",
    ]
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for config in configurations:
            for workflow in workflows:
                subset = [r for r in rows if r["configuration"] == config and r["workflow"] == workflow]
                benign = [r for r in subset if r["task_type"] == "benign"]
                adversarial = [r for r in subset if r["task_type"] == "adversarial"]
                writer.writerow({
                    "configuration": config,
                    "workflow": workflow,
                    "benign_attempts": len(benign),
                    "adversarial_attempts": len(adversarial),
                    "ASR": f"{pct(sum(int(r['unauthorized_action_executed']) for r in adversarial), len(adversarial)):.1f}%",
                    "TSR": f"{pct(sum(int(r['benign_task_completed'] or 0) for r in benign), len(benign)):.1f}%",
                    "FDR": f"{pct(sum(int(r['benign_request_denied'] or 0) for r in benign), len(benign)):.1f}%",
                    "DVR": f"{pct(sum(int(r['delegation_scope_denial']) for r in adversarial), len(adversarial)):.1f}%",
                    "mean_latency_ms": f"{statistics.mean(float(r['latency_ms']) for r in subset):.6f}",
                })
    return True


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
