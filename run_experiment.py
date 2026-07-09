#!/usr/bin/env python3
"""Generate the controlled IBA authorization-level evaluation corpus.

The generator loads workflow, attack, tool, and policy definitions from YAML.
Attack labels are used only while constructing scenario records. The PEP receives
only a mediated ToolRequest and a policy name; it never receives workflow,
task type, or attack labels.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import platform
import random
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "configs"
RESULT_DIR = ROOT / "results"
LATEX_DIR = ROOT / "latex"
RESULT_DIR.mkdir(exist_ok=True)
LATEX_DIR.mkdir(exist_ok=True)

# These identifiers select deterministic surface-form variants. They are not
# stochastic model runs and do not select scenario outcomes.
SEEDS = [1, 2, 3]
CREDENTIAL_SIGNING_KEY = b"iba-artifact-test-credential-key-v2"
CONTEXT_SIGNING_KEY = b"iba-artifact-test-context-key-v2"
BENCH_WARMUP = 50
BENCH_BATCHES = 5
BENCH_REPEATS = 200

FIELDS = [
    "seed", "surface_variant", "run_id", "case_id", "workflow", "configuration",
    "task_type", "attack_type", "agent_chain", "actor_agent", "request_text",
    "provenance", "allowed_provenance", "provenance_valid",
    "requested_action", "requested_resource", "request_constraints",
    "true_user_operations", "true_user_resources", "true_user_action_scopes",
    "intended_operations", "intended_resources", "intended_action_scopes",
    "intended_constraints", "constraints_valid",
    "delegated_operations", "delegated_resources", "delegated_action_scopes",
    "context_fault", "context_signature_valid", "nonce_fresh", "tool_hash_match",
    "policy_bundle_match", "sandbox_approved", "runtime_measurement_match",
    "context_valid", "credential_valid", "delegated_scope_valid", "intent_match",
    "decision", "denial_reason", "unauthorized_action_executed",
    "benign_task_completed", "benign_request_denied", "delegation_scope_denial",
    "context_spoof_blocked", "latency_ms",
]


def load_yaml(name: str) -> dict[str, Any]:
    with (CONFIG_DIR / name).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{name} must contain a YAML mapping")
    return data


WORKFLOWS = load_yaml("workflows.yaml")["workflows"]
ATTACK_SCENARIOS = load_yaml("attacks.yaml")["scenarios"]
TOOLS = load_yaml("tools.yaml")["tools"]
POLICIES = load_yaml("policies.yaml")["policies"]
CONFIG_ORDER = list(POLICIES)
WORKFLOW_ORDER = list(WORKFLOWS)
ATTACK_ORDER = list(dict.fromkeys(case["attack_type"] for case in ATTACK_SCENARIOS))
ATTACK_CASES = {
    (workflow, attack): [
        case for case in ATTACK_SCENARIOS
        if case["workflow"] == workflow and case["attack_type"] == attack
    ]
    for workflow in WORKFLOW_ORDER
    for attack in ATTACK_ORDER
}
POLICY_BUNDLE_HASH = hashlib.sha256((CONFIG_DIR / "policies.yaml").read_bytes()).hexdigest()


def normalize_set(values: Iterable[str]) -> frozenset[str]:
    return frozenset(str(v).strip() for v in values if str(v).strip())


def normalize_scopes(values: Iterable[Any]) -> frozenset[tuple[str, str]]:
    scopes: set[tuple[str, str]] = set()
    for item in values:
        if isinstance(item, dict):
            action, resource = item["action"], item["resource"]
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            action, resource = item
        elif isinstance(item, str) and "|" in item:
            action, resource = item.split("|", 1)
        else:
            raise ValueError(f"invalid action scope: {item!r}")
        scopes.add((str(action).strip(), str(resource).strip()))
    return frozenset(scopes)


def fmt_set(values: Iterable[str]) -> str:
    return "{" + ", ".join(sorted(normalize_set(values))) + "}"


def fmt_scopes(values: Iterable[Any]) -> str:
    return "{" + ", ".join(f"{a}|{r}" for a, r in sorted(normalize_scopes(values))) + "}"


def resource_match(requested: str, allowed: str) -> bool:
    requested = str(requested).strip()
    allowed = str(allowed).strip()
    return requested == allowed or (allowed.endswith("*") and requested.startswith(allowed[:-1]))


def scope_allowed(action: str, resource: str, scopes: Iterable[Any]) -> bool:
    action = str(action).strip()
    resource = str(resource).strip()
    return any(action == allowed_action and resource_match(resource, allowed_resource)
               for allowed_action, allowed_resource in normalize_scopes(scopes))


def scopes_to_ops_resources(scopes: Iterable[Any]) -> tuple[frozenset[str], frozenset[str]]:
    normalized = normalize_scopes(scopes)
    return normalize_set(a for a, _ in normalized), normalize_set(r for _, r in normalized)


def intent_hash(
    action_scopes: Iterable[Any], constraints: Iterable[str], allowed_provenance: Iterable[str]
) -> str:
    payload = {
        "action_scopes": sorted([list(pair) for pair in normalize_scopes(action_scopes)]),
        "constraints": sorted(normalize_set(constraints)),
        "allowed_provenance": sorted(normalize_set(allowed_provenance)),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class IntentManager:
    """Conservative deterministic extractor used by the controlled corpus."""

    VAGUE_CUES = (
        "handle the", "take care of what is needed", "take care of anything needed",
        "whatever is necessary", "do whatever is needed",
    )
    REMEDIATION_CUES = (
        "fix the issue end to end", "resolve the problem fully", "remediate the issue completely",
    )

    def extract(
        self, request_text: str, workflow: dict[str, Any]
    ) -> tuple[frozenset[tuple[str, str]], frozenset[str], frozenset[str]]:
        text = request_text.lower()
        scopes = set(normalize_scopes(workflow["true_action_scopes"]))
        constraints = normalize_set(workflow["intent_constraints"])
        allowed_provenance = normalize_set(workflow["allowed_provenance"])

        if any(cue in text for cue in self.REMEDIATION_CUES):
            scopes.add(tuple(workflow["remediation_pair"]))
            return normalize_scopes(scopes), constraints, allowed_provenance
        if any(cue in text for cue in self.VAGUE_CUES):
            return frozenset(), constraints, allowed_provenance
        return normalize_scopes(scopes), constraints, allowed_provenance


class CredentialManager:
    def issue(
        self, *, subject: str, holder: str, intent_digest: str,
        allowed_actions: Iterable[Any], nonce: str,
    ) -> dict[str, Any]:
        claims = {
            "subject": subject,
            "holder": holder,
            "intent_hash": intent_digest,
            "allowed_actions": [list(pair) for pair in sorted(normalize_scopes(allowed_actions))],
            "nonce": nonce,
            "version": 2,
        }
        raw = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(CREDENTIAL_SIGNING_KEY, raw, hashlib.sha256).hexdigest()
        return {"claims": claims, "signature": signature}

    def delegate(
        self, *, parent: dict[str, Any], holder: str,
        allowed_actions: Iterable[Any], nonce: str,
    ) -> dict[str, Any]:
        claims = parent["claims"]
        digest = str(claims["intent_hash"])
        if not self.verify(parent, digest):
            raise ValueError("cannot delegate from an invalid parent credential")
        parent_actions = normalize_scopes(claims["allowed_actions"])
        child_actions = normalize_scopes(allowed_actions)
        if not child_actions.issubset(parent_actions):
            raise ValueError("child credential expands parent action-resource authority")
        return self.issue(
            subject=str(claims["subject"]), holder=holder, intent_digest=digest,
            allowed_actions=child_actions, nonce=nonce,
        )

    def verify(self, credential: dict[str, Any], expected_intent_hash: str) -> bool:
        try:
            claims = credential["claims"]
            signature = credential["signature"]
            raw = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected = hmac.new(CREDENTIAL_SIGNING_KEY, raw, hashlib.sha256).hexdigest()
            return hmac.compare_digest(signature, expected) and claims["intent_hash"] == expected_intent_hash
        except (KeyError, TypeError, ValueError):
            return False


class ContextVerifier:
    """Verify signed nonce-tagged synthetic context evidence and replay freshness."""

    REQUIRED_MEASUREMENTS = (
        "tool_hash", "policy_bundle_hash", "sandbox_configuration", "runtime_measurement", "nonce"
    )

    def __init__(self) -> None:
        self._consumed_nonces: set[str] = set()

    def reset_replay_cache(self) -> None:
        self._consumed_nonces.clear()

    def expected_measurements(
        self, *, actor: str, action: str, seed: int, case_id: str, configuration: str
    ) -> dict[str, str]:
        tool_doc = json.dumps(TOOLS[action], sort_keys=True, separators=(",", ":"))
        return {
            "tool_hash": hashlib.sha256(f"{action}:{tool_doc}".encode("utf-8")).hexdigest(),
            "policy_bundle_hash": POLICY_BUNDLE_HASH,
            "sandbox_configuration": "sandbox-v1",
            "runtime_measurement": hashlib.sha256(f"runtime-v1:{actor}".encode("utf-8")).hexdigest(),
            # Configuration is part of the synthetic invocation identity so each paired
            # configuration receives a fresh nonce while evaluating the same scenario.
            "nonce": hashlib.sha256(
                f"{seed}:{case_id}:{configuration}:nonce".encode("utf-8")
            ).hexdigest()[:24],
        }

    def sign(self, measurements: dict[str, str]) -> dict[str, Any]:
        normalized = {key: str(measurements[key]) for key in self.REQUIRED_MEASUREMENTS}
        raw = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = hmac.new(CONTEXT_SIGNING_KEY, raw, hashlib.sha256).hexdigest()
        return {"measurements": normalized, "signature": signature}

    def inspect(self, evidence: dict[str, Any], expected: dict[str, str]) -> dict[str, bool]:
        try:
            measurements = evidence["measurements"]
            signature = str(evidence["signature"])
            raw = json.dumps(measurements, sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected_signature = hmac.new(CONTEXT_SIGNING_KEY, raw, hashlib.sha256).hexdigest()
            signature_valid = hmac.compare_digest(signature, expected_signature)
            nonce = str(measurements.get("nonce", ""))
            nonce_fresh = bool(nonce) and nonce not in self._consumed_nonces and nonce == expected["nonce"]
            checks = {
                "context_signature_valid": signature_valid,
                "nonce_fresh": nonce_fresh,
                "tool_hash_match": measurements.get("tool_hash") == expected["tool_hash"],
                "policy_bundle_match": measurements.get("policy_bundle_hash") == expected["policy_bundle_hash"],
                "sandbox_approved": measurements.get("sandbox_configuration") == expected["sandbox_configuration"],
                "runtime_measurement_match": measurements.get("runtime_measurement") == expected["runtime_measurement"],
            }
            checks["context_valid"] = all(checks.values())
            return checks
        except (KeyError, TypeError, ValueError):
            return {
                "context_signature_valid": False, "nonce_fresh": False,
                "tool_hash_match": False, "policy_bundle_match": False,
                "sandbox_approved": False, "runtime_measurement_match": False,
                "context_valid": False,
            }

    def verify(self, evidence: dict[str, Any], expected: dict[str, str], *, consume_nonce: bool) -> bool:
        checks = self.inspect(evidence, expected)
        if not checks["context_valid"]:
            return False
        if consume_nonce:
            self._consumed_nonces.add(str(evidence["measurements"]["nonce"]))
        return True


@dataclass(frozen=True)
class ToolRequest:
    actor_agent: str
    requested_action: str
    requested_resource: str
    request_constraints: frozenset[str]
    intended_action_scopes: frozenset[tuple[str, str]]
    intended_constraints: frozenset[str]
    provenance: str
    allowed_provenance: frozenset[str]
    delegated_action_scopes: frozenset[tuple[str, str]]
    credential: dict[str, Any]
    context_evidence: dict[str, Any]
    expected_context: dict[str, str]


class PolicyEnforcementPoint:
    """Configuration-driven PEP. No attack/workflow/task labels enter authorize()."""

    def __init__(self) -> None:
        self.credential_manager = CredentialManager()
        self.context_verifier = ContextVerifier()

    def predicates(self, request: ToolRequest) -> dict[str, bool]:
        digest = intent_hash(
            request.intended_action_scopes, request.intended_constraints, request.allowed_provenance
        )
        context_checks = self.context_verifier.inspect(request.context_evidence, request.expected_context)
        pair_valid = scope_allowed(
            request.requested_action, request.requested_resource, request.intended_action_scopes
        )
        constraints_valid = request.request_constraints.issubset(request.intended_constraints)
        provenance_valid = request.provenance in request.allowed_provenance
        return {
            "credential_valid": self.credential_manager.verify(request.credential, digest),
            **context_checks,
            "delegated_scope_valid": scope_allowed(
                request.requested_action, request.requested_resource, request.delegated_action_scopes
            ),
            "constraints_valid": constraints_valid,
            "provenance_valid": provenance_valid,
            "intent_match": pair_valid and constraints_valid and provenance_valid,
        }

    def authorize(
        self, configuration: str, request: ToolRequest, *, consume_context: bool = True
    ) -> tuple[str, str]:
        checks = POLICIES[configuration]["checks"]
        if not checks:
            return "allow", "none"
        if "identity" in checks and request.actor_agent not in TOOLS[request.requested_action]["roles"]:
            return "deny", "role_not_allowed"
        if "allowlist" in checks and not bool(TOOLS[request.requested_action]["allowlisted"]):
            return "deny", "tool_not_allowed"

        digest = intent_hash(
            request.intended_action_scopes, request.intended_constraints, request.allowed_provenance
        )
        if "credential" in checks and not self.credential_manager.verify(request.credential, digest):
            return "deny", "invalid_credential"
        if "context" in checks and not self.context_verifier.verify(
            request.context_evidence, request.expected_context, consume_nonce=consume_context
        ):
            return "deny", "invalid_context"
        if "delegation" in checks and not scope_allowed(
            request.requested_action, request.requested_resource, request.delegated_action_scopes
        ):
            return "deny", "delegation_scope_violation"
        if "intent" in checks:
            pair_valid = scope_allowed(
                request.requested_action, request.requested_resource, request.intended_action_scopes
            )
            constraints_valid = request.request_constraints.issubset(request.intended_constraints)
            provenance_valid = request.provenance in request.allowed_provenance
            if not (pair_valid and constraints_valid and provenance_valid):
                return "deny", "intent_mismatch"
        return "allow", "none"


INTENT_MANAGER = IntentManager()
CREDENTIAL_MANAGER = CredentialManager()
CONTEXT_VERIFIER = ContextVerifier()
PEP = PolicyEnforcementPoint()


def active_agent_for(action: str, agent_chain: str, task_type: str) -> str:
    chain = agent_chain.split("->")
    if task_type == "benign":
        for agent in chain:
            if agent in TOOLS[action]["roles"]:
                return agent
        return TOOLS[action]["roles"][0]
    return chain[-1]


def perturb_context(evidence: dict[str, Any], fault: str) -> dict[str, Any]:
    if not fault or fault == "none":
        return {"measurements": dict(evidence["measurements"]), "signature": evidence["signature"]}
    measurements = dict(evidence["measurements"])
    mapping = {
        "stale_nonce": ("nonce", "stale-nonce"),
        "tool_hash": ("tool_hash", "mismatched-tool-hash"),
        "policy_bundle": ("policy_bundle_hash", "modified-policy-bundle"),
        "sandbox": ("sandbox_configuration", "unapproved-sandbox"),
        "runtime": ("runtime_measurement", "unexpected-runtime"),
    }
    key, value = mapping[fault]
    measurements[key] = value
    # The evidence object remains correctly signed but describes stale/mismatched
    # measurements. Verification therefore tests both authenticity and expected state.
    return CONTEXT_VERIFIER.sign(measurements)


def seeded_surface(base_surface: str, seed: int, case_id: str) -> str:
    """Apply one deterministic neutral surface-form variant."""
    rng = random.Random(f"{seed}:{case_id}")
    prefixes = ["", "For this run, ", "In the current task, "]
    prefix = rng.choice(prefixes)
    if not prefix:
        return base_surface
    return prefix + base_surface[0].lower() + base_surface[1:]


def _invalidate_credential(credential: dict[str, Any]) -> dict[str, Any]:
    corrupted = {"claims": dict(credential["claims"]), "signature": credential["signature"]}
    corrupted["signature"] = "0" * len(str(corrupted["signature"]))
    return corrupted


def build_task(
    seed: int, workflow_name: str, configuration: str,
    task_type: str, case: dict[str, Any], attack_type: str,
) -> dict[str, Any]:
    workflow = WORKFLOWS[workflow_name]
    true_scopes = normalize_scopes(workflow["true_action_scopes"])
    true_ops, true_res = scopes_to_ops_resources(true_scopes)
    agent_chain = workflow["agent_chain"]
    case_id = case["id"]
    request_text = seeded_surface(case["request_text"], seed, case_id)
    action = str(case["requested_action"])
    resource = str(case["requested_resource"])
    intended_scopes, intended_constraints, allowed_provenance = INTENT_MANAGER.extract(request_text, workflow)

    if task_type == "benign":
        delegated_scopes = normalize_scopes(set(true_scopes) | {(action, resource)})
        context_fault = "none"
        expected_context_valid = True
        expected_credential_valid = True
        expected_delegated_scope_valid = True
        provenance = "user_request"
        request_constraints = normalize_set(workflow["intent_constraints"])
    else:
        if case["workflow"] != workflow_name or case["attack_type"] != attack_type:
            raise ValueError(f"Scenario {case_id} is indexed under the wrong workflow/attack")
        intended_scopes = normalize_scopes(
            set(intended_scopes) | set(normalize_scopes(case.get("intent_add_actions", [])))
        )
        expected_context_valid = bool(case["context_valid"])
        expected_credential_valid = bool(case["credential_valid"])
        expected_delegated_scope_valid = bool(case["delegated_scope_valid"])
        context_fault = str(case.get("context_fault", "none"))
        provenance = str(case.get("provenance", "unknown"))
        request_constraints = normalize_set(
            set(workflow["intent_constraints"]) | set(case.get("required_constraints", []))
        )
        if expected_delegated_scope_valid:
            delegated_scopes = normalize_scopes(set(true_scopes) | {(action, resource)})
        else:
            delegated_scopes = true_scopes

        actual_true_authorized = scope_allowed(action, resource, true_scopes)
        if actual_true_authorized != bool(case["true_user_authorized"]):
            raise ValueError(
                f"Scenario {case_id} true_user_authorized={case['true_user_authorized']} "
                f"but YAML workflow pair authority computes {actual_true_authorized}"
            )
        if expected_context_valid and context_fault != "none":
            raise ValueError(f"Scenario {case_id} marks context valid but context_fault={context_fault}")
        if not expected_context_valid and context_fault == "none":
            raise ValueError(f"Scenario {case_id} marks context invalid without an explicit context_fault")

    actor = active_agent_for(action, agent_chain, task_type)
    expected_context = CONTEXT_VERIFIER.expected_measurements(
        actor=actor, action=action, seed=seed, case_id=case_id, configuration=configuration
    )
    context_evidence = CONTEXT_VERIFIER.sign(expected_context)
    context_evidence = perturb_context(context_evidence, context_fault)

    digest = intent_hash(intended_scopes, intended_constraints, allowed_provenance)
    parent_scopes = normalize_scopes(set(intended_scopes) | set(delegated_scopes))
    parent_credential = CREDENTIAL_MANAGER.issue(
        subject=workflow["subject"], holder=agent_chain.split("->")[0],
        intent_digest=digest, allowed_actions=parent_scopes, nonce=expected_context["nonce"],
    )
    credential = CREDENTIAL_MANAGER.delegate(
        parent=parent_credential, holder=actor,
        allowed_actions=delegated_scopes, nonce=expected_context["nonce"],
    )
    if not expected_credential_valid:
        credential = _invalidate_credential(credential)

    task = {
        "seed": seed, "surface_variant": f"variant_{seed}", "case_id": case_id,
        "workflow": workflow_name, "task_type": task_type, "attack_type": attack_type,
        "agent_chain": agent_chain, "actor_agent": actor, "request_text": request_text,
        "provenance": provenance, "allowed_provenance": allowed_provenance,
        "requested_action": action, "requested_resource": resource,
        "request_constraints": request_constraints,
        "true_user_action_scopes": true_scopes,
        "true_user_operations": true_ops, "true_user_resources": true_res,
        "intended_action_scopes": intended_scopes,
        "intended_constraints": intended_constraints,
        "delegated_action_scopes": normalize_scopes(credential["claims"]["allowed_actions"]),
        "context_fault": context_fault, "credential": credential,
        "context_evidence": context_evidence, "expected_context": expected_context,
    }

    probe = make_request(task)
    actual = PEP.predicates(probe)
    if actual["context_valid"] != expected_context_valid:
        raise ValueError(f"Scenario {case_id} context_valid mismatch")
    if actual["credential_valid"] != expected_credential_valid:
        raise ValueError(f"Scenario {case_id} credential_valid mismatch")
    if actual["delegated_scope_valid"] != expected_delegated_scope_valid:
        raise ValueError(f"Scenario {case_id} delegated_scope_valid mismatch")
    return task


def make_request(task: dict[str, Any]) -> ToolRequest:
    return ToolRequest(
        actor_agent=task["actor_agent"], requested_action=task["requested_action"],
        requested_resource=task["requested_resource"], request_constraints=task["request_constraints"],
        intended_action_scopes=task["intended_action_scopes"],
        intended_constraints=task["intended_constraints"], provenance=task["provenance"],
        allowed_provenance=task["allowed_provenance"],
        delegated_action_scopes=task["delegated_action_scopes"], credential=task["credential"],
        context_evidence=task["context_evidence"], expected_context=task["expected_context"],
    )


BENCHMARK_CACHE: dict[tuple[Any, ...], float] = {}


def benchmark_authorization(configuration: str, request: ToolRequest, predicates: dict[str, bool]) -> float:
    """Measure median per-call PEP latency without consuming replay state.

    Repeated timing of an identical request necessarily reuses its nonce. The benchmark
    therefore exercises all signature, measurement, scope, provenance, constraint, and
    policy checks with consume_context=False; corpus execution itself uses replay state.
    """
    key = (
        configuration, request.actor_agent, request.requested_action, request.requested_resource,
        tuple(sorted(request.request_constraints)), tuple(sorted(request.intended_action_scopes)),
        tuple(sorted(request.intended_constraints)), request.provenance,
        tuple(sorted(request.allowed_provenance)), tuple(sorted(request.delegated_action_scopes)),
        predicates["credential_valid"], predicates["context_valid"],
        predicates["delegated_scope_valid"], predicates["intent_match"],
    )
    if key in BENCHMARK_CACHE:
        return BENCHMARK_CACHE[key]
    for _ in range(BENCH_WARMUP):
        PEP.authorize(configuration, request, consume_context=False)
    samples: list[float] = []
    for _ in range(BENCH_BATCHES):
        start = time.perf_counter_ns()
        for _ in range(BENCH_REPEATS):
            PEP.authorize(configuration, request, consume_context=False)
        elapsed = time.perf_counter_ns() - start
        samples.append((elapsed / BENCH_REPEATS) / 1_000_000.0)
    measured = statistics.median(samples)
    BENCHMARK_CACHE[key] = measured
    return measured


def task_to_row(task: dict[str, Any], configuration: str, run_index: int) -> dict[str, Any]:
    request = make_request(task)
    predicates = PEP.predicates(request)
    latency_ms = benchmark_authorization(configuration, request, predicates)
    decision, denial_reason = PEP.authorize(configuration, request, consume_context=True)

    true_user_allows = scope_allowed(
        request.requested_action, request.requested_resource, task["true_user_action_scopes"]
    )
    delegation_allows = predicates["delegated_scope_valid"]
    unauthorized = (
        task["task_type"] == "adversarial" and decision == "allow"
        and (not true_user_allows or not delegation_allows)
    )
    benign_completed: int | str = ""
    benign_denied: int | str = ""
    if task["task_type"] == "benign":
        benign_completed = int(decision == "allow")
        benign_denied = int(decision == "deny")

    intended_ops, intended_res = scopes_to_ops_resources(task["intended_action_scopes"])
    delegated_ops, delegated_res = scopes_to_ops_resources(task["delegated_action_scopes"])

    return {
        "seed": task["seed"], "surface_variant": task["surface_variant"],
        "run_id": f"s{task['seed']:02d}-{configuration}-{run_index:05d}", "case_id": task["case_id"],
        "workflow": task["workflow"], "configuration": configuration,
        "task_type": task["task_type"], "attack_type": task["attack_type"],
        "agent_chain": task["agent_chain"], "actor_agent": task["actor_agent"],
        "request_text": task["request_text"], "provenance": task["provenance"],
        "allowed_provenance": fmt_set(task["allowed_provenance"]),
        "provenance_valid": str(predicates["provenance_valid"]).lower(),
        "requested_action": task["requested_action"], "requested_resource": task["requested_resource"],
        "request_constraints": fmt_set(task["request_constraints"]),
        "true_user_operations": fmt_set(task["true_user_operations"]),
        "true_user_resources": fmt_set(task["true_user_resources"]),
        "true_user_action_scopes": fmt_scopes(task["true_user_action_scopes"]),
        "intended_operations": fmt_set(intended_ops), "intended_resources": fmt_set(intended_res),
        "intended_action_scopes": fmt_scopes(task["intended_action_scopes"]),
        "intended_constraints": fmt_set(task["intended_constraints"]),
        "constraints_valid": str(predicates["constraints_valid"]).lower(),
        "delegated_operations": fmt_set(delegated_ops), "delegated_resources": fmt_set(delegated_res),
        "delegated_action_scopes": fmt_scopes(task["delegated_action_scopes"]),
        "context_fault": task["context_fault"] or "none",
        "context_signature_valid": str(predicates["context_signature_valid"]).lower(),
        "nonce_fresh": str(predicates["nonce_fresh"]).lower(),
        "tool_hash_match": str(predicates["tool_hash_match"]).lower(),
        "policy_bundle_match": str(predicates["policy_bundle_match"]).lower(),
        "sandbox_approved": str(predicates["sandbox_approved"]).lower(),
        "runtime_measurement_match": str(predicates["runtime_measurement_match"]).lower(),
        "context_valid": str(predicates["context_valid"]).lower(),
        "credential_valid": str(predicates["credential_valid"]).lower(),
        "delegated_scope_valid": str(predicates["delegated_scope_valid"]).lower(),
        "intent_match": str(predicates["intent_match"]).lower(), "decision": decision,
        "denial_reason": denial_reason, "unauthorized_action_executed": int(unauthorized),
        "benign_task_completed": benign_completed, "benign_request_denied": benign_denied,
        "delegation_scope_denial": int(
            task["task_type"] == "adversarial" and denial_reason == "delegation_scope_violation"
        ),
        "context_spoof_blocked": int(
            task["task_type"] == "adversarial" and task["attack_type"] == "context_spoofing"
            and decision == "deny" and denial_reason == "invalid_context"
        ),
        "latency_ms": f"{latency_ms:.6f}",
    }


class AuditLog:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def append(self, row: dict[str, Any]) -> None:
        self.rows.append(row)

    def write(self, path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(self.rows)


def generate() -> list[dict[str, Any]]:
    BENCHMARK_CACHE.clear()
    PEP.context_verifier.reset_replay_cache()
    all_log = AuditLog()
    for seed in SEEDS:
        seed_log = AuditLog()
        run_index = 0
        for configuration in CONFIG_ORDER:
            for workflow_name in WORKFLOW_ORDER:
                workflow = WORKFLOWS[workflow_name]
                for case in workflow["benign_cases"]:
                    task = build_task(seed, workflow_name, configuration, "benign", case, "none")
                    row = task_to_row(task, configuration, run_index)
                    seed_log.append(row); all_log.append(row); run_index += 1
                for attack_type in ATTACK_ORDER:
                    for case in ATTACK_CASES[(workflow_name, attack_type)]:
                        task = build_task(seed, workflow_name, configuration, "adversarial", case, attack_type)
                        row = task_to_row(task, configuration, run_index)
                        seed_log.append(row); all_log.append(row); run_index += 1
        seed_log.write(RESULT_DIR / f"evaluation_results_seed{seed}.csv")
    all_log.write(RESULT_DIR / "evaluation_results_all_seeds.csv")
    all_log.write(RESULT_DIR / "evaluation_results.csv")
    return all_log.rows


def write_benchmark_environment() -> None:
    """Record the environment for the supplemental latency microbenchmark."""
    processor = platform.processor().strip() or "unavailable"
    machine = platform.machine().strip() or "unavailable"
    lines = [
        "IBA authorization-path microbenchmark environment",
        "================================================",
        f"python_version: {platform.python_version()}",
        f"python_implementation: {platform.python_implementation()}",
        f"platform: {platform.platform()}",
        f"operating_system: {platform.system()} {platform.release()}",
        f"machine_architecture: {machine}",
        f"processor_identifier: {processor}",
        f"benchmark_warmup_iterations: {BENCH_WARMUP}",
        f"benchmark_batches: {BENCH_BATCHES}",
        f"benchmark_repetitions_per_batch: {BENCH_REPEATS}",
        "timing_clock: time.perf_counter_ns",
        "reported_statistic: median per-call latency across timed batches",
        "scope: local Python PolicyEnforcementPoint.authorize path only",
        "portable_performance_claim: no",
        "note: timings are supplemental feasibility evidence and are hardware/runtime dependent",
    ]
    (RESULT_DIR / "benchmark_environment.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_checksums() -> None:
    lines: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if path.name == "checksums_sha256.txt":
            continue
        if "__pycache__" in relative.parts or ".git" in relative.parts:
            continue
        if path.suffix in {".pyc", ".pyo"} or path.name == ".DS_Store":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {relative}")
    (RESULT_DIR / "checksums_sha256.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> bool:
    rows = generate()
    from aggregate_attack_breakdown import main as aggregate_attack
    from aggregate_tables import main as aggregate_tables
    from aggregate_workflow_breakdown import main as aggregate_workflow
    from independent_semantic_audit import main as independent_audit
    from validate_results import main as validate_results

    aggregate_attack(); aggregate_workflow(); aggregate_tables()
    write_benchmark_environment()
    validation_ok = validate_results()
    audit_ok = independent_audit()
    write_checksums()
    print(f"Rows {len(rows)}")
    print(f"Validation OK {validation_ok}")
    print(f"Independent audit OK {audit_ok}")
    print((LATEX_DIR / "abstract_sentence.txt").read_text(encoding="utf-8").strip())
    return validation_ok and audit_ok


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
