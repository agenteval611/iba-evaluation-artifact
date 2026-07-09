#!/usr/bin/env python3
from __future__ import annotations

import csv
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "results" / "evaluation_results_all_seeds.csv"
OUTPUT = ROOT / "results" / "attack_breakdown.csv"


def pct(n: int, d: int) -> float:
    return 0.0 if d == 0 else 100.0 * n / d


def main() -> bool:
    with INPUT.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    configurations = list(dict.fromkeys(r["configuration"] for r in rows))
    attacks = list(dict.fromkeys(r["attack_type"] for r in rows if r["attack_type"] != "none"))
    fields = [
        "configuration", "attack_type", "adversarial_attempts",
        "unauthorized_actions_executed", "ASR", "delegation_scope_denials",
        "DVR", "context_spoof_attempts", "context_spoof_blocked", "CSBR",
        "mean_latency_ms",
    ]
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for config in configurations:
            for attack in attacks:
                subset = [
                    r for r in rows
                    if r["configuration"] == config
                    and r["task_type"] == "adversarial"
                    and r["attack_type"] == attack
                ]
                attempts = len(subset)
                unauthorized = sum(int(r["unauthorized_action_executed"]) for r in subset)
                delegation_denials = sum(int(r["delegation_scope_denial"]) for r in subset)
                context_attempts = attempts if attack == "context_spoofing" else 0
                context_blocked = sum(int(r["context_spoof_blocked"]) for r in subset)
                writer.writerow({
                    "configuration": config,
                    "attack_type": attack,
                    "adversarial_attempts": attempts,
                    "unauthorized_actions_executed": unauthorized,
                    "ASR": f"{pct(unauthorized, attempts):.1f}%",
                    "delegation_scope_denials": delegation_denials,
                    "DVR": f"{pct(delegation_denials, attempts):.1f}%",
                    "context_spoof_attempts": context_attempts,
                    "context_spoof_blocked": context_blocked,
                    "CSBR": "" if context_attempts == 0 else f"{pct(context_blocked, context_attempts):.1f}%",
                    "mean_latency_ms": f"{statistics.mean(float(r['latency_ms']) for r in subset):.6f}",
                })
    return True


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
