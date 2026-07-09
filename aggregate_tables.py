#!/usr/bin/env python3
from __future__ import annotations

import csv
import statistics
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
LATEX = ROOT / "latex"
INPUT = RESULTS / "evaluation_results_all_seeds.csv"


def pct(n: int, d: int) -> float:
    return 0.0 if d == 0 else 100.0 * n / d


def per_seed_metrics(rows: list[dict[str, str]], config: str, seed: int) -> dict[str, float]:
    subset = [r for r in rows if r["configuration"] == config and int(r["seed"]) == seed]
    benign = [r for r in subset if r["task_type"] == "benign"]
    adversarial = [r for r in subset if r["task_type"] == "adversarial"]
    return {
        "ASR": pct(sum(int(r["unauthorized_action_executed"]) for r in adversarial), len(adversarial)),
        "TSR": pct(sum(int(r["benign_task_completed"] or 0) for r in benign), len(benign)),
        "FDR": pct(sum(int(r["benign_request_denied"] or 0) for r in benign), len(benign)),
        "DVR": pct(sum(int(r["delegation_scope_denial"]) for r in adversarial), len(adversarial)),
        "latency_ms": statistics.mean(float(r["latency_ms"]) for r in subset),
    }


def main() -> bool:
    with INPUT.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    policy_data = yaml.safe_load((ROOT / "configs" / "policies.yaml").read_text(encoding="utf-8"))["policies"]
    config_order = list(policy_data)
    seeds = sorted({int(r["seed"]) for r in rows})

    seed_metrics: dict[str, list[dict[str, float]]] = {
        config: [per_seed_metrics(rows, config, seed) for seed in seeds]
        for config in config_order
    }
    baseline_latency = statistics.mean(m["latency_ms"] for m in seed_metrics["no_enforcement"])

    metrics = []
    for config in config_order:
        items = seed_metrics[config]
        metric = {
            "configuration": config,
            "Configuration": policy_data[config]["label"],
            "ASR": statistics.mean(m["ASR"] for m in items),
            "ASR_std": statistics.pstdev(m["ASR"] for m in items),
            "TSR": statistics.mean(m["TSR"] for m in items),
            "TSR_std": statistics.pstdev(m["TSR"] for m in items),
            "FDR": statistics.mean(m["FDR"] for m in items),
            "FDR_std": statistics.pstdev(m["FDR"] for m in items),
            "DVR": statistics.mean(m["DVR"] for m in items),
            "DVR_std": statistics.pstdev(m["DVR"] for m in items),
            "mean_latency_ms": statistics.mean(m["latency_ms"] for m in items),
        }
        metric["overhead_ms"] = metric["mean_latency_ms"] - baseline_latency
        metrics.append(metric)

    summary_fields = [
        "configuration", "Configuration", "mean_ASR", "std_ASR", "mean_TSR", "std_TSR",
        "mean_FDR", "std_FDR", "mean_DVR", "std_DVR", "mean_latency_ms", "mean_overhead_ms",
    ]
    with (RESULTS / "summary_metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=summary_fields)
        writer.writeheader()
        for m in metrics:
            writer.writerow({
                "configuration": m["configuration"],
                "Configuration": m["Configuration"],
                "mean_ASR": f"{m['ASR']:.3f}",
                "std_ASR": f"{m['ASR_std']:.3f}",
                "mean_TSR": f"{m['TSR']:.3f}",
                "std_TSR": f"{m['TSR_std']:.3f}",
                "mean_FDR": f"{m['FDR']:.3f}",
                "std_FDR": f"{m['FDR_std']:.3f}",
                "mean_DVR": f"{m['DVR']:.3f}",
                "std_DVR": f"{m['DVR_std']:.3f}",
                "mean_latency_ms": f"{m['mean_latency_ms']:.6f}",
                "mean_overhead_ms": f"{m['overhead_ms']:.6f}",
            })

    with (RESULTS / "latency_microbenchmark.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["Configuration", "mean_latency_ms", "overhead_vs_no_enforcement_ms"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for m in metrics:
            writer.writerow({
                "Configuration": m["Configuration"],
                "mean_latency_ms": f"{m['mean_latency_ms']:.6f}",
                "overhead_vs_no_enforcement_ms": f"{m['overhead_ms']:+.6f}",
            })

    with (RESULTS / "table1_main_results.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["Configuration", "ASR", "TSR", "FDR", "DVR"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for m in metrics:
            writer.writerow({
                "Configuration": m["Configuration"],
                "ASR": f"{m['ASR']:.1f}%",
                "TSR": f"{m['TSR']:.1f}%",
                "FDR": f"{m['FDR']:.1f}%",
                "DVR": f"{m['DVR']:.1f}%",
            })

    ablation = ["no_enforcement", "intent_only", "context_only", "intent_context_no_attenuation", "full_iba"]
    component_map = {
        "no_enforcement": ("No", "No", "No"),
        "intent_only": ("Yes", "No", "No"),
        "context_only": ("No", "Yes", "No"),
        "intent_context_no_attenuation": ("Yes", "Yes", "No"),
        "full_iba": ("Yes", "Yes", "Yes"),
    }
    by_config = {m["configuration"]: m for m in metrics}
    with (RESULTS / "table2_ablation_results.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["Configuration", "Intent", "Context", "Attenuation", "ASR", "TSR"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for config in ablation:
            m = by_config[config]
            intent, context, attenuation = component_map[config]
            writer.writerow({
                "Configuration": m["Configuration"],
                "Intent": intent,
                "Context": context,
                "Attenuation": attenuation,
                "ASR": f"{m['ASR']:.1f}%",
                "TSR": f"{m['TSR']:.1f}%",
            })

    partial = [m for m in metrics if m["configuration"] != "full_iba" and m["TSR"] >= 90.0]
    strongest = min(
        partial,
        key=lambda m: (m["ASR"], -len(policy_data[m["configuration"]]["checks"])),
    )
    full = by_config["full_iba"]
    abstract = (
        "Compared with the strongest partial-enforcement baseline, full IBA reduces ASR "
        f"from {strongest['ASR']:.1f}% to {full['ASR']:.1f}% while maintaining TSR of {full['TSR']:.1f}%."
    )
    (LATEX / "abstract_sentence.txt").write_text(abstract + "\n", encoding="utf-8")

    table1 = [
        r"\begin{table}[t]", r"\centering",
        r"\caption{Main evaluation results across all workflow families.}",
        r"\label{tab:main-results}", r"\begin{tabular}{lcccc}", r"\hline",
        r"\textbf{Configuration} & \textbf{ASR} & \textbf{TSR} & \textbf{FDR} & \textbf{DVR} \\",
        r"\hline",
    ]
    for m in metrics:
        table1.append(
            f"{m['Configuration']} & {m['ASR']:.1f}\\% & {m['TSR']:.1f}\\% & "
            f"{m['FDR']:.1f}\\% & {m['DVR']:.1f}\\% " + r"\\"
        )
    table1 += [r"\hline", r"\end{tabular}", r"\end{table}"]
    (LATEX / "table1_main_results.tex").write_text("\n".join(table1) + "\n", encoding="utf-8")

    table2 = [
        r"\begin{table}[t]", r"\centering", r"\caption{Ablation study of IBA components.}",
        r"\label{tab:ablation-results}", r"\begin{tabular}{lccccc}", r"\hline",
        r"\textbf{Configuration} & \textbf{Intent} & \textbf{Context} & \textbf{Attenuation} & \textbf{ASR} & \textbf{TSR} \\",
        r"\hline",
    ]
    for config in ablation:
        m = by_config[config]
        intent, context, attenuation = component_map[config]
        table2.append(
            f"{m['Configuration']} & {intent} & {context} & {attenuation} & "
            f"{m['ASR']:.1f}\\% & {m['TSR']:.1f}\\% " + r"\\"
        )
    table2 += [r"\hline", r"\end{tabular}", r"\end{table}"]
    (LATEX / "table2_ablation_results.tex").write_text("\n".join(table2) + "\n", encoding="utf-8")

    paper = f"""# Paper-ready evaluation text

## Section 7.1 Experimental Setup

The evaluation uses a controlled authorization-level simulator rather than production traces or a deployed LLM-agent stack. Agent delegation and protected-tool requests are represented as mediated action records generated from YAML-defined workflow and attack cases. This design executes the same controlled task corpus under all seven enforcement configurations while isolating intent binding, context verification, and delegation attenuation. Attack labels are used only for scenario generation and result grouping; the policy enforcement point receives no attack, workflow, or task-type label. Authorization decisions depend on explicit action-resource scope membership, intent constraints, allowed provenance, credential verification, signed nonce-tagged context evidence, delegated action scope, and the active policy configuration. The corpus contains 5,040 execution rows across three deterministic surface-form variants, four workflow families, seven configurations, and six attack categories.

## Section 7.6 Main Results

{abstract} Remaining Full IBA failures occur under overbroad intent extraction, where ambiguous remediation wording causes the extracted structured intent itself to include an operation or resource outside the effective user-authorized request. This is consistent with the enforcement boundary: IBA enforces the structured intent presented to the PEP but does not prove semantic intent extraction is perfect. In the evaluated corpus, Full IBA blocks mediated direct-prompt, indirect-prompt, tool-output-poisoning, context-spoofing, and delegation-drift cases under the stated threat-model assumptions. A supplemental local Python microbenchmark measures the authorization path with `time.perf_counter_ns()` after warm-up. Because these microsecond-scale timings are hardware- and runtime-dependent, we use them only as implementation-level feasibility evidence rather than as a portable primary performance estimate; they are reported in the artifact rather than the main results table.

## Conclusion metric update

In the controlled authorization-level evaluation, full IBA lowers attack success from {strongest['ASR']:.1f}% for the strongest partial-enforcement baseline to {full['ASR']:.1f}%, while preserving a benign task-success rate of {full['TSR']:.1f}%. The remaining successful in-scope unauthorized executions arise only in the overbroad-intent-extraction cases, underscoring that enforcement of a structured intent does not establish the semantic correctness of the extraction step itself.
"""
    (ROOT / "paper_paragraphs.md").write_text(paper, encoding="utf-8")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
