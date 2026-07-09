#!/usr/bin/env python3
"""CSV-only semantic audit using only the Python standard library."""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "results" / "evaluation_results_all_seeds.csv"
OUTPUT = ROOT / "results" / "independent_semantic_audit_report.txt"


def parse_set(value: str) -> set[str]:
    text = str(value).strip().strip("{}[]()")
    if not text:
        return set()
    sep = ";" if ";" in text else ","
    return {p.strip().strip("'\"") for p in text.split(sep) if p.strip().strip("'\"")}


def parse_scopes(value: str) -> set[tuple[str, str]]:
    scopes = set()
    for item in parse_set(value):
        if "|" not in item:
            raise ValueError(f"invalid scope encoding: {item!r}")
        action, resource = item.split("|", 1)
        scopes.add((action.strip(), resource.strip()))
    return scopes


def bval(value: str) -> bool:
    return str(value).strip().lower() == "true"


def resource_match(requested: str, allowed: str) -> bool:
    return requested == allowed or (allowed.endswith("*") and requested.startswith(allowed[:-1]))


def scope_allowed(action: str, resource: str, scopes: str) -> bool:
    return any(action == a and resource_match(resource, r) for a, r in parse_scopes(scopes))


def expected_intent(row: dict[str, str]) -> bool:
    pair_ok = scope_allowed(row["requested_action"], row["requested_resource"], row["intended_action_scopes"])
    constraints_ok = parse_set(row["request_constraints"]).issubset(parse_set(row["intended_constraints"]))
    provenance_ok = row["provenance"] in parse_set(row["allowed_provenance"])
    return pair_ok and constraints_ok and provenance_ok


def expected_full_decision(row: dict[str, str]) -> tuple[str, str]:
    if not bval(row["credential_valid"]):
        return "deny", "invalid_credential"
    if not bval(row["context_valid"]):
        return "deny", "invalid_context"
    if not bval(row["delegated_scope_valid"]):
        return "deny", "delegation_scope_violation"
    if not bval(row["intent_match"]):
        return "deny", "intent_mismatch"
    return "allow", "none"


def main() -> bool:
    with INPUT.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    intent_bad = full_intent_bad = full_decision_bad = full_reason_bad = 0
    unauthorized_bad = full_unauthorized = full_outside_overbroad = 0
    provenance_bad = constraints_bad = delegation_bad = 0

    for row in rows:
        expected = expected_intent(row)
        if bval(row["intent_match"]) != expected:
            intent_bad += 1
            if row["configuration"] == "full_iba":
                full_intent_bad += 1
        if bval(row["provenance_valid"]) != (row["provenance"] in parse_set(row["allowed_provenance"])):
            provenance_bad += 1
        if bval(row["constraints_valid"]) != parse_set(row["request_constraints"]).issubset(parse_set(row["intended_constraints"])):
            constraints_bad += 1
        expected_delegation = scope_allowed(
            row["requested_action"], row["requested_resource"], row["delegated_action_scopes"]
        )
        if bval(row["delegated_scope_valid"]) != expected_delegation:
            delegation_bad += 1

        if row["configuration"] == "full_iba":
            decision, reason = expected_full_decision(row)
            full_decision_bad += int(row["decision"] != decision)
            full_reason_bad += int(row["denial_reason"] != reason)

        true_user_allows = scope_allowed(
            row["requested_action"], row["requested_resource"], row["true_user_action_scopes"]
        )
        delegation_allows = expected_delegation
        expected_unauthorized = int(
            row["task_type"] == "adversarial" and row["decision"] == "allow"
            and (not true_user_allows or not delegation_allows)
        )
        unauthorized_bad += int(int(row["unauthorized_action_executed"]) != expected_unauthorized)
        if row["configuration"] == "full_iba" and int(row["unauthorized_action_executed"]) == 1:
            full_unauthorized += 1
            if row["attack_type"] != "overbroad_intent_extraction":
                full_outside_overbroad += 1

    ok = not any([
        intent_bad, full_intent_bad, full_decision_bad, full_reason_bad,
        unauthorized_bad, provenance_bad, constraints_bad, delegation_bad,
        full_outside_overbroad,
    ])
    report = [
        "Independent semantic audit report",
        "=================================",
        "This report is computed from results/evaluation_results_all_seeds.csv only.",
        "The script imports only Python standard-library modules and does not import simulator decision logic.",
        "",
        f"total_rows: {len(rows)}",
        f"surface_variants: {sorted({row['surface_variant'] for row in rows})}",
        f"intent_match inconsistencies: {intent_bad}",
        f"Full IBA intent_match inconsistencies: {full_intent_bad}",
        f"provenance predicate inconsistencies: {provenance_bad}",
        f"constraint predicate inconsistencies: {constraints_bad}",
        f"delegated action-scope inconsistencies: {delegation_bad}",
        f"Full IBA decision-rule mismatches: {full_decision_bad}",
        f"Full IBA denial-reason mismatches: {full_reason_bad}",
        f"unauthorized_action_executed recomputation mismatches: {unauthorized_bad}",
        f"Full IBA unauthorized executions: {full_unauthorized}",
        f"Full IBA unauthorized executions outside overbroad_intent_extraction: {full_outside_overbroad}",
        f"audit_status: {'PASS' if ok else 'FAIL'}",
    ]
    OUTPUT.write_text("\n".join(report) + "\n", encoding="utf-8")
    print(f"Independent semantic audit: {'PASS' if ok else 'FAIL'}")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
