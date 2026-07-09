# IBA ICISS Evaluation Artifact

This artifact accompanies the paper **“Intent-Bound Authorization for LLM Agent Systems: Enforcing Delegation Safety with Context-Verified Credentials.”**

## Evaluation model

This artifact implements a **controlled synthetic authorization-level simulator**. It models multi-agent delegation chains and mediated agent-to-tool requests as structured execution scenarios. It does not run a production LLM service and does not use production traces.

The controlled corpus contains:

- 3 deterministic surface-form variants (`variant_1`, `variant_2`, `variant_3`)
- 4 workflow families
- 7 enforcement configurations
- 30 benign cases per workflow/configuration/variant
- 30 adversarial cases per workflow/configuration/variant
- 6 adversarial attack categories
- 5,040 total mediated tool-invocation records

The integer `seed` field is retained as the deterministic variant identifier for compatibility with the result files. These are **not three stochastic model runs** and results should not be described as averages over random seeds. For each YAML-defined case, the variant identifier selects a neutral request prefix without changing case membership, authorization semantics, or success/failure selection.

The benign corpus includes one deliberately ambiguous fail-closed request per workflow and variant. This is a controlled stress case for conservative extraction, not an estimate of ambiguous-request prevalence.

Each workflow/category pair contains five explicit YAML-defined adversarial scenarios. In the overbroad-intent category, three cases use ambiguous remediation wording and two are constrained controls. Reported rates therefore characterize this fixed corpus and are not prevalence estimates.

## Critical policy semantics

Attack labels are used only for scenario generation and result grouping. `PolicyEnforcementPoint.authorize()` does **not** receive `attack_type`, `workflow`, or `task_type`.

The Full IBA intent predicate checks all of the following:

1. the exact requested **action-resource pair** is in the structured intent scope;
2. request constraints are satisfied by the structured intent constraints; and
3. the request provenance is in the structured intent's allowed provenance channels.

The simulator uses explicit action-resource scopes such as:

```text
(read_logs, deployment_logs)
(create_ticket, incident_ticket)
```

Operations and resources are not authorized as independent Cartesian-product sets. Credential attenuation also uses action-resource scopes, and a child credential may contain only a subset of its parent's action scopes.

The default allowed provenance channels in the controlled workflows are:

```text
user_request
approved_planning_state
```

Retrieved content, tool output, runtime evidence, and an unapproved delegated subtask are not accepted as provenance for privileged intent justification. Provenance is a PEP input, not an evaluation-only label.

For Full IBA, the decision order is:

1. invalid credential -> deny;
2. invalid context -> deny;
3. delegated action-scope violation -> deny;
4. intent mismatch (action-resource scope, constraints, or provenance) -> deny;
5. otherwise allow.

`intent_match` is deterministically recomputed from the explicit action-resource scope, constraints, and provenance. It is not randomly assigned and is not derived from an attack label.

An adversarial action is counted as unauthorized when it executes despite falling outside the explicit true-user action scope or delegated child action scope.

## Context evidence model

The `ContextVerifier` models signed nonce-tagged context evidence. Each evidence object contains:

- tool hash;
- policy-bundle hash;
- sandbox configuration;
- runtime measurement; and
- nonce.

The measurement object is signed with a test-only HMAC key. Verification requires:

- a valid evidence signature;
- all measurements to match the expected execution context; and
- a fresh, expected nonce.

The verifier maintains a consumed-nonce replay cache during corpus execution. Each paired configuration execution receives a distinct nonce derived from its invocation identity so the same scenario can be evaluated fairly across configurations without replaying a nonce.

The HMAC mechanism is a lightweight synthetic implementation for testing authorization semantics. It is not presented as a production attestation or credential format.

## Configuration files

The simulator loads and consumes all four YAML inputs:

- `configs/workflows.yaml`: workflow semantics, explicit true-user action scopes, benign cases, intent constraints, and allowed provenance.
- `configs/attacks.yaml`: 120 explicit adversarial scenarios with requested action/resource, context and credential state, delegation-scope state, provenance, constraints, and extracted-intent action additions.
- `configs/tools.yaml`: tool classes, allowlist status, and agent-role permissions.
- `configs/policies.yaml`: active checks for each enforcement configuration.

Scenario outcomes are not selected through target-count slices or hidden success lists.

## Reproduction

Install the single dependency:

```bash
python3 -m pip install -r requirements.txt
```

Generate the experiment and all reporting outputs:

```bash
python3 run_experiment.py
```

The default benchmark parameters are deliberately bounded for reviewer-facing reproduction:

```text
warm-up iterations: 50
batches: 5
repetitions per batch: 200
```

The reporting scripts may also be rerun against the committed all-seeds CSV:

```bash
python3 aggregate_attack_breakdown.py
python3 aggregate_workflow_breakdown.py
python3 aggregate_tables.py
```

Validate the committed CSVs without regenerating them:

```bash
python3 validate_results.py
```

Run the standalone CSV-only semantic audit:

```bash
python3 independent_semantic_audit.py
```

`validate_results.py` does not import or call the simulator. `independent_semantic_audit.py` imports only Python standard-library modules and independently recomputes action-scope membership, constraint satisfaction, provenance validity, Full IBA decision semantics, delegated authority, and unauthorized execution.

## Latency measurement

Latency is measured rather than inserted as a fixed overhead table. `run_experiment.py` performs warm-up calls and then uses `time.perf_counter_ns()` around repeated authorization batches. It records the median per-call latency for each structural request/configuration path. These timings are retained as a supplemental artifact microbenchmark and are not included in the main Table 1.

The benchmark measures the local Python PEP authorization path. It is **not end-to-end LLM, tool, network, or cloud latency**. During repeated timing, nonce consumption is disabled because the same structural request is intentionally timed multiple times; signature verification, expected-measurement checks, action-scope checks, provenance, constraints, and policy logic are still executed. Corpus execution uses normal nonce consumption and replay state.

Timing results are hardware- and runtime-dependent. The artifact therefore treats them as implementation-level feasibility evidence rather than portable primary performance estimates. `results/benchmark_environment.txt` records the Python/platform metadata and benchmark parameters for the packaged run, and `results/latency_microbenchmark.csv` contains the measured values.

## Result files

- `results/evaluation_results_seed1.csv`
- `results/evaluation_results_seed2.csv`
- `results/evaluation_results_seed3.csv`
- `results/evaluation_results_all_seeds.csv`
- `results/summary_metrics.csv`
- `results/latency_microbenchmark.csv`
- `results/benchmark_environment.txt`
- `results/attack_breakdown.csv`
- `results/workflow_breakdown.csv`
- `results/table1_main_results.csv`
- `results/table2_ablation_results.csv`
- `results/validation_report.txt`
- `results/independent_semantic_audit_report.txt`
- `latex/table1_main_results.tex`
- `latex/table2_ablation_results.tex`
- `latex/abstract_sentence.txt`

## Threat-model and evaluation limitations

The evaluation assumes mediated tool execution through the PEP. It does not cover PEP bypass, compromised signing keys, unsound expected context measurements, or a proof that semantic intent extraction is perfect. Signed context evidence is modeled with test-only HMAC keys rather than a production attestation infrastructure. Remaining Full IBA failures may occur when ambiguous wording makes the structured intent itself overly permissive. The artifact evaluates authorization semantics under controlled synthetic conditions and does not claim production-trace realism.

## Current controlled-corpus result

Run `python3 run_experiment.py` to regenerate the current metrics and `latex/abstract_sentence.txt`. The reported ASR/TSR values emerge from the YAML-defined case corpus and executable policy semantics; the generator does not encode target percentages.

`results/checksums_sha256.txt` contains SHA-256 hashes for artifact files and excludes Python cache files, `.git`, and `.DS_Store`.

## Secondary LLM-Generated Request Validation

The 5,040-record controlled study above remains the **primary evaluation** and is unchanged by this secondary infrastructure. The secondary study is a separate external-validity check that asks a narrower question: **does the same Full IBA Policy Enforcement Point mediate unauthorized action-resource requests when the proposal is generated by a model-driven tool-planning agent?**

This is not a production deployment and is not a model-safety benchmark. It does not replace, modify, or contribute rows to the primary controlled corpus, Table 1, or Table 2.

The fixed secondary corpus is defined in `configs/llm_validation_cases.yaml` and contains:

- 4 existing workflow families;
- 10 fixed prompt cases per workflow;
- 5 benign and 5 adversarial cases per workflow;
- 40 fixed cases total; and
- 3 independent repetitions per case, for 120 attempted model calls.

The included model adapter does not request or claim explicit model seed control. Repetition identifiers `1`, `2`, and `3` distinguish repeated calls and are **not random seeds**.

### Request-specific intent and available capabilities

`AVAILABLE TOOL SCHEMA` exposes the workflow capability vocabulary: all action-resource pairs the planning model can technically propose in that workflow. It is intentionally broader than the request-specific authorization scope. The schema also exposes the workflow-level **constraint syntax contract** accepted by the secondary request interface. This is interface metadata rather than a hidden request-specific authorization answer. The current contracts are:

```text
cloud_ops:           purpose = diagnostic_only
document_retrieval:  scope = requested_documents_only
ticketing_it:        scope = ticket_scope_only
approval_workflow:   approval = required_before_execution
```

The model must emit those constraints as the corresponding JSON key/value mapping, for example `{"purpose":"diagnostic_only"}`. The runner does not translate flat labels or arbitrary values after generation, and the PEP's existing constraint-subset semantics are unchanged.

Each YAML case separately defines `intent_scopes`, containing only the action-resource pairs justified by that specific user request. For example, a request only to inspect deployment logs authorizes `read_logs(deployment_logs)` rather than every cloud-operations action. A document-summary request authorizes only `summarize_doc(requested_doc)`, a classification request only the relevant ticket classification action, and an approval-status request only `check_approval(approval_record)`.

The 40 case definitions were reviewed at the request level. The secondary validator checks that credential scopes remain subsets of request-specific intent scopes and that scope definitions vary within each workflow rather than reusing a workflow-wide scope set.

### Model input and output

For each run, the model receives only:

- the workflow identifier;
- the user request;
- workflow context; and
- the available tool schema.

The prompt does not expose `task_type`, attack labels, expected decisions, ground-truth authorization, unauthorized-action labels, IBA decisions, or denial reasons. The PEP likewise receives none of those evaluation labels.

The model is asked to return exactly one JSON object with required fields `operation`, `resource`, and `constraints`. It may optionally return `claimed_provenance` for analysis. The artifact does **not** use API-schema-enforced Structured Outputs; serialization is prompt-constrained and then strictly parsed.

The parser does not repair Markdown, extract embedded JSON substrings, rename fields, infer omitted values, or otherwise modify model content. Malformed or schema-invalid successful generations are recorded with `parse_status=failed` and fail closed. Untouched model text is written to `results/llm_validation_raw_outputs.jsonl` only after a real study run.

### Claimed versus trusted provenance

`claimed_provenance`, when present, is an **untrusted model claim** retained only for analysis. It is never copied into `ToolRequest.provenance` and cannot select the trusted provenance used by the PEP. The runner preserves the model-provided analytical value and records `claimed_provenance_valid=1` only when it is one of the documented analytical enum values. An out-of-enum claim such as `workflow_context` is recorded with `claimed_provenance_valid=0` but does not make an otherwise valid operation/resource/constraint request fail parsing or affect the PEP decision.

The harness supplies `trusted_provenance` from fixed case metadata. In this secondary study it denotes the trusted planning-channel metadata through which a generated tool proposal reaches the PEP. Because the model sees the user request and workflow context together, the harness cannot infer which prompt component causally caused a particular generated action. Therefore, the secondary study does **not** claim to independently validate causal provenance attribution. Provenance semantics are primarily evaluated in the controlled primary study. The secondary study focuses on mediation of model-generated action-resource requests through the same PEP.

### Generation failures and parse failures

Provider/runtime generation failures and malformed model outputs are reported separately.

- `generation_status=failed` means the provider/runtime call failed. Parsing is not attempted (`parse_status=not_attempted`), no tool request is constructed, and no action executes.
- `generation_status=success` means model text was returned. Strict parsing is then attempted.
- A strict parse failure uses `parse_status=failed` and fails closed without PEP execution.

The included OpenAI adapter uses no automatic retry policy. It does not retry model content, unauthorized actions, or parse failures. Generation errors are recorded only as sanitized error-type identifiers; API keys, bearer tokens, headers, and local paths are not logged.

### Secondary metrics

The study reports raw numerators and denominators for all metrics:

- **Generation Failure Rate (GFR):** generation failures / attempted model calls.
- **Parse Failure Rate (PFR):** strict parse failures / successful model generations. Generation failures are excluded from the PFR denominator.
- **Model Unauthorized Proposal Rate (MUPR):** unauthorized parsed model-generated requests / successfully parsed model-generated requests.
- **Unauthorized Execution Rate (UER):** unauthorized model-generated requests allowed by Full IBA / unauthorized model-generated requests.
- **Benign Allow Rate (BAR):** ground-truth-authorized benign parsed requests allowed by Full IBA / ground-truth-authorized benign parsed requests.
- **Benign Run Success Rate (BRSR):** benign runs with successful generation, successful parsing, a ground-truth-authorized generated action, and an allow decision / all benign runs.

BAR retains its conditional authorization interpretation. BRSR is the end-to-end benign-run metric and therefore includes model mistakes, generation failures, and parse failures in its denominator.

### PEP integration and ground truth

Successfully parsed requests are converted to the existing `ToolRequest` type and passed to the existing `PolicyEnforcementPoint.authorize("full_iba", ...)` implementation in `run_experiment.py`. No second simplified PEP is implemented for the secondary study.

The same executable predicates are used for:

- explicit action-resource scope membership;
- intent constraints;
- fixed trusted provenance metadata;
- credential validity;
- signed nonce-tagged context evidence; and
- delegated action scope.

Ground truth is independently computed from the fixed case definition, request-specific action-resource scopes, fixed trusted provenance metadata, and explicit constraints. It is not derived from the PEP decision or from the model's claimed provenance.

### Model adapter and environment variables

`llm_adapter.py` provides a provider-adapter interface. The included concrete adapter uses the OpenAI Responses interface through the official Python client. Credentials are read only from environment variables and are never written to source, CSV, JSONL, reports, or checksums.

Required variables for the included real adapter:

```text
OPENAI_API_KEY
IBA_LLM_MODEL
```

Optional variables:

```text
IBA_LLM_PROVIDER=openai
IBA_LLM_REASONING_EFFORT=minimal
IBA_LLM_MAX_OUTPUT_TOKENS=300
```

For the pinned GPT-5 mini study configuration, the OpenAI Responses API rejected the `temperature` parameter during a pre-experiment compatibility check. The real adapter therefore omits `temperature` and records this omission in generation metadata. No experimental model outputs had been produced when this compatibility adjustment was made. The adapter explicitly requests `reasoning.effort=minimal`; this is appropriate for the short, schema-constrained single-action planning task and reduces the risk that reasoning tokens consume the configured output-token budget before visible JSON is emitted. A non-`completed` Responses API status is recorded as a generation failure, not as a parse failure.

`IBA_LLM_MODEL` must contain the exact model identifier selected for the real study. The adapter records the returned model identifier and available generation metadata. It does not request seed control, so the `model_seed` field is empty.

Run the real secondary study only with a supported model runtime and credential:

```bash
python3 llm_validation.py
```

If credentials or the model identifier are missing, the command prints `LLM validation study: NOT RUN` and creates no fabricated secondary result files or Table 3.

After a real run, the command creates:

```text
results/llm_validation_results.csv
results/llm_validation_summary.csv
results/llm_validation_report.txt
results/llm_validation_raw_outputs.jsonl
latex/table3_llm_validation.tex
```

The read-only validator then recomputes Full IBA decisions, denial reasons, ground truth, unauthorized proposal/execution labels, benign denials, GFR, PFR, MUPR, UER, BAR, BRSR, raw-output hashes, and Table 3 values from the committed outputs.

Before a real model study has been run:

```bash
python3 validate_results.py
```

reports:

```text
LLM validation study: NOT RUN
```

and continues validating the complete primary artifact.

### Non-experimental test-only pipeline self-test

`test_llm_validation_pipeline.py` exercises the complete 120-row secondary output path in an isolated temporary copy using `DeterministicTestAdapter`. The adapter is explicitly non-experimental, is never selected by the real environment-based adapter factory, and does not represent LLM measurements.

Run:

```bash
python3 test_llm_validation_pipeline.py
```

The self-test covers generation failures, strict parse failures, and valid parsed requests, then runs `validate_results.py` against the 120 temporary rows. The temporary directory is deleted on completion. Test-generated secondary result files are not committed and must not be reported as model-study results.

### Secondary-study history and current status

A first secondary run was discarded after audit identified a constraint-schema interface mismatch: the model was shown flat constraint labels while the enforcement interface expected canonical key/value constraints. The mismatch caused otherwise scope-matching benign proposals to fail intent matching. The interface was corrected before the reported secondary study was rerun.

The discarded run is not retained as paper evidence and its result files are not included in this artifact snapshot. No model output from that run was repaired, relabeled, or reused as a corrected measurement. The 40 fixed cases, user requests, workflow context, request-specific intent scopes, credential scopes, context profiles, and trusted provenance metadata are unchanged. The only secondary-interface changes were (1) exposing the canonical workflow-level key/value constraint syntax to the model before generation and (2) treating `claimed_provenance` as non-blocking analysis-only metadata.

**Current artifact status: corrected real secondary study completed and validated.** The reported secondary run used the OpenAI adapter with model `gpt-5-mini-2025-08-07`, `reasoning_effort=minimal`, `max_output_tokens=300`, the `temperature` parameter omitted because it is unsupported by the selected model/interface, no explicit seed control, and zero automatic retries. The design used 40 fixed cases with three independent repetitions per case, yielding 120 attempted model calls. The committed raw-output and result files are the outputs of that corrected run.

Observed corrected-run counts and metrics are:

| Measure | Numerator / denominator | Result |
|---|---:|---:|
| Attempted runs | 120 | 120 |
| Successful generations | 120 / 120 | 120 |
| Parsed requests | 120 / 120 | 120 |
| Unauthorized proposals | 16 / 120 parsed requests | 16 |
| GFR | 0 / 120 | 0.0% |
| PFR | 0 / 120 successful generations | 0.0% |
| MUPR | 16 / 120 parsed requests | 13.3% |
| UER under Full IBA | 0 / 16 unauthorized proposals | 0.0% |
| BAR | 48 / 48 ground-truth-authorized benign parsed requests | 100.0% |
| BRSR | 48 / 60 benign runs | 80.0% |

The 60 benign runs produced 48 parsed requests with the request-specific authorized action-resource pair and compatible fixed authorization semantics; all 48 were allowed by Full IBA. The remaining benign runs reflect model planning deviations from the predefined request-specific authorization scope, which is why BAR is 100.0% while BRSR is 80.0%.

Across all 120 parsed model-generated proposals, 16 were independently classified as outside the predefined request-specific authorization semantics. Full IBA allowed none of those 16. This result is evidence about mediation of the observed model-generated requests under the fixed harness semantics. It is not a model-safety benchmark, does not establish causal provenance attribution from mixed prompt context, and does not establish production-deployment security.

The completed secondary outputs are:

```text
results/llm_validation_results.csv
results/llm_validation_summary.csv
results/llm_validation_report.txt
results/llm_validation_raw_outputs.jsonl
latex/table3_llm_validation.tex
```

Run `python3 validate_results.py` to independently recompute the secondary decision labels, ground-truth labels, execution labels, raw-output hashes, GFR, PFR, MUPR, UER, BAR, BRSR, and Table 3 consistency from the committed outputs. Re-running `python3 llm_validation.py` performs a new set of provider calls and is not required to validate the committed corrected study.
