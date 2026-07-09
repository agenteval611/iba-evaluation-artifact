#!/usr/bin/env python3
"""NON-EXPERIMENTAL isolated self-test for the secondary LLM pipeline.

The test copies the artifact into a temporary directory, executes all 120
secondary rows with DeterministicTestAdapter, runs the read-only validator, and
then deletes the temporary copy. No test-generated secondary measurements are
committed or presented as LLM results.
"""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(command: list[str], cwd: Path) -> None:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(command)}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )


def main() -> bool:
    with tempfile.TemporaryDirectory(prefix="iba-llm-test-") as tmp:
        test_root = Path(tmp) / "artifact"
        shutil.copytree(
            ROOT,
            test_root,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.pyo", "*.zip", ".DS_Store", ".env"),
        )
        for relative in [
            "results/llm_validation_results.csv",
            "results/llm_validation_summary.csv",
            "results/llm_validation_report.txt",
            "results/llm_validation_raw_outputs.jsonl",
            "latex/table3_llm_validation.tex",
        ]:
            path = test_root / relative
            if path.exists():
                path.unlink()

        runner = (
            "from llm_adapter import DeterministicTestAdapter; "
            "from llm_validation import run_study; "
            "raise SystemExit(0 if run_study(DeterministicTestAdapter()) else 1)"
        )
        run([sys.executable, "-c", runner], test_root)
        run([sys.executable, "validate_results.py"], test_root)

        results_path = test_root / "results" / "llm_validation_results.csv"
        with results_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        if len(rows) != 120:
            raise RuntimeError(f"test-only secondary pipeline produced {len(rows)} rows; expected 120")

        parsed_rows = [row for row in rows if row["parse_status"] == "parsed"]
        if not any(row["claimed_provenance"] == "workflow_context" and row["claimed_provenance_valid"] == "0" for row in parsed_rows):
            raise RuntimeError("test-only pipeline did not exercise non-blocking invalid claimed_provenance")
        if not any(json.loads(row["constraints_json"]) for row in parsed_rows):
            raise RuntimeError("test-only pipeline did not exercise canonical key/value constraints")
        if not any(row["unauthorized_generated"] == "1" for row in parsed_rows):
            raise RuntimeError("test-only pipeline did not exercise unauthorized action-resource proposals")
        if not any(row["context_valid"] == "0" for row in parsed_rows):
            raise RuntimeError("test-only pipeline did not exercise context failure")
        if not any(
            row["task_type"] == "benign"
            and row["ground_truth_authorized"] == "1"
            and row["pep_decision"] == "allow"
            for row in parsed_rows
        ):
            raise RuntimeError("test-only pipeline did not exercise successful benign allow behavior")

        delegation_probe = (
            "from dataclasses import replace; "
            "from llm_validation import load_cases, build_pep_request, WORKFLOW_CONSTRAINT_SCHEMAS, strict_parse, global_resource_registry; "
            "from run_experiment import PolicyEnforcementPoint; "
            "import json; "
            "cases=load_cases(); case=cases[0]; pep=PolicyEnforcementPoint(); "
            "payload=json.dumps({'operation':'read_logs','resource':'deployment_logs','constraints':{'purpose':'diagnostic_only'},'claimed_provenance':'workflow_context'}); "
            "parsed,err=strict_parse(payload, resource_registry=global_resource_registry(cases), constraint_schema=WORKFLOW_CONSTRAINT_SCHEMAS['cloud_ops']); "
            "req=build_pep_request(pep=pep, case=case, parsed=parsed, repetition=1); "
            "req=replace(req, delegated_action_scopes=frozenset()); "
            "decision,reason=pep.authorize('full_iba', req, consume_context=False); "
            "raise SystemExit(0 if (decision,reason)==('deny','delegation_scope_violation') else 1)"
        )
        run([sys.executable, "-c", delegation_probe], test_root)

        report = (test_root / "results" / "validation_report.txt").read_text(encoding="utf-8")
        required = [
            "LLM validation study: RUN",
            "LLM Full IBA decision inconsistencies: 0",
            "LLM unauthorized-execution recomputation mismatches: 0",
            "LLM benign-denial recomputation mismatches: 0",
            "LLM constraint-schema consistency check: passed",
            "LLM claimed-provenance analytical-field check: passed",
            "LLM intent-predicate recomputation mismatches: 0",
            "LLM summary recomputation check: passed",
            "LLM Table 3 consistency check: passed",
            "No validation errors found.",
        ]
        missing = [line for line in required if line not in report]
        if missing:
            raise RuntimeError(f"test-only validation report missing expected checks: {missing}")

    print("Test-only LLM validation pipeline: PASS (120 isolated rows; outputs discarded)")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
