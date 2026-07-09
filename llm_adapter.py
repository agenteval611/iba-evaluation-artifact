#!/usr/bin/env python3
"""Provider adapters for the secondary model-generated request validation study.

Credentials are read only from environment variables. This module never writes
credentials, bearer tokens, request headers, or local filesystem paths to
experimental outputs.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ModelResponse:
    model_id: str
    raw_text: str
    generation_metadata: dict[str, Any] = field(default_factory=dict)
    seed: int | None = None
    error: str | None = None


class ModelAdapter(Protocol):
    model_id: str

    def generate_tool_request(
        self, *, system_prompt: str, user_prompt: str, repetition: int
    ) -> ModelResponse:
        ...


class AdapterConfigurationError(RuntimeError):
    """Raised when no supported model runtime is configured."""


class OpenAIResponsesAdapter:
    """OpenAI Responses API adapter using the official Python client.

    The adapter deliberately does not request or claim seed control. The study
    therefore records three independent repetitions, not random seeds.
    """

    def __init__(self, *, api_key: str, model_id: str, reasoning_effort: str, max_output_tokens: int) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise AdapterConfigurationError(
                "The openai package is required for IBA_LLM_PROVIDER=openai. "
                "Install requirements.txt before running the secondary study."
            ) from exc
        self._client = OpenAI(api_key=api_key)
        self.model_id = model_id
        self.reasoning_effort = reasoning_effort
        self.max_output_tokens = max_output_tokens

    @classmethod
    def from_environment(cls) -> "OpenAIResponsesAdapter":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        model_id = os.getenv("IBA_LLM_MODEL", "").strip()
        if not api_key:
            raise AdapterConfigurationError(
                "OPENAI_API_KEY is not set. The LLM validation study has not been executed; "
                "no synthetic model outputs will be generated."
            )
        if not model_id:
            raise AdapterConfigurationError(
                "IBA_LLM_MODEL is not set. Set it to the exact model identifier to record in the study."
            )
        reasoning_effort = os.getenv("IBA_LLM_REASONING_EFFORT", "minimal").strip().lower()
        if reasoning_effort not in {"minimal", "low", "medium", "high"}:
            raise AdapterConfigurationError(
                "IBA_LLM_REASONING_EFFORT must be one of: minimal, low, medium, high."
            )
        try:
            max_output_tokens = int(os.getenv("IBA_LLM_MAX_OUTPUT_TOKENS", "300"))
        except ValueError as exc:
            raise AdapterConfigurationError(
                "IBA_LLM_MAX_OUTPUT_TOKENS must be an integer."
            ) from exc
        if max_output_tokens <= 0:
            raise AdapterConfigurationError("IBA_LLM_MAX_OUTPUT_TOKENS must be positive.")
        return cls(
            api_key=api_key,
            model_id=model_id,
            reasoning_effort=reasoning_effort,
            max_output_tokens=max_output_tokens,
        )

    def generate_tool_request(
        self, *, system_prompt: str, user_prompt: str, repetition: int
    ) -> ModelResponse:
        del repetition  # no seed control is requested or claimed by this adapter
        try:
            response = self._client.responses.create(
                model=self.model_id,
                instructions=system_prompt,
                input=user_prompt,
                reasoning={"effort": self.reasoning_effort},
                max_output_tokens=self.max_output_tokens,
            )
            usage = getattr(response, "usage", None)
            if hasattr(usage, "model_dump"):
                usage = usage.model_dump()
            status = str(getattr(response, "status", ""))
            incomplete_details = getattr(response, "incomplete_details", None)
            if hasattr(incomplete_details, "model_dump"):
                incomplete_details = incomplete_details.model_dump()
            metadata = {
                "provider": "openai",
                "response_id": str(getattr(response, "id", "")),
                "status": status,
                "incomplete_details": incomplete_details if isinstance(incomplete_details, dict) else {},
                "usage": usage if isinstance(usage, dict) else {},
                "temperature_parameter": "omitted_unsupported_by_selected_model",
                "reasoning_effort": self.reasoning_effort,
                "max_output_tokens": self.max_output_tokens,
                "seed_control": False,
                "retry_count": 0,
            }
            if status != "completed":
                reason = "unknown"
                if isinstance(incomplete_details, dict):
                    reason = str(incomplete_details.get("reason", "unknown"))
                error_type = f"OpenAIResponse_{status or 'unknown'}_{reason}"
                return ModelResponse(
                    model_id=str(getattr(response, "model", self.model_id)),
                    raw_text=str(getattr(response, "output_text", "")),
                    generation_metadata={**metadata, "error_type": error_type},
                    seed=None,
                    error=error_type,
                )
            return ModelResponse(
                model_id=str(getattr(response, "model", self.model_id)),
                raw_text=str(getattr(response, "output_text", "")),
                generation_metadata=metadata,
                seed=None,
                error=None,
            )
        except Exception as exc:  # generation failure; no synthetic response is invented
            return ModelResponse(
                model_id=self.model_id,
                raw_text="",
                generation_metadata={
                    "provider": "openai",
                    "temperature_parameter": "omitted_unsupported_by_selected_model",
                    "reasoning_effort": self.reasoning_effort,
                    "max_output_tokens": self.max_output_tokens,
                    "seed_control": False,
                    "retry_count": 0,
                    "error_type": type(exc).__name__,
                },
                seed=None,
                error=type(exc).__name__,
            )


class DeterministicTestAdapter:
    """NON-EXPERIMENTAL TEST-ONLY adapter for validator/pipeline self-tests.

    It never represents an LLM study and is never selected by
    :func:`adapter_from_environment`. The isolated test harness uses this class
    only to exercise generation failures, strict parse failures, and valid JSON
    through the complete 120-row secondary pipeline.
    """

    model_id = "TEST_ONLY_DETERMINISTIC_ADAPTER"

    def generate_tool_request(
        self, *, system_prompt: str, user_prompt: str, repetition: int
    ) -> ModelResponse:
        del system_prompt
        metadata = {
            "provider": "test_only",
            "test_only": True,
            "seed_control": False,
            "retry_count": 0,
        }

        request_text = user_prompt.split("USER REQUEST\n", 1)[1].split("\n\nWORKFLOW CONTEXT", 1)[0]
        if repetition == 1 and request_text.startswith("Search the document index"):
            return ModelResponse(
                model_id=self.model_id,
                raw_text="",
                generation_metadata={**metadata, "error_type": "TestGenerationFailure"},
                seed=None,
                error="TestGenerationFailure",
            )
        if repetition == 2 and request_text.startswith("Read the requested document"):
            return ModelResponse(
                model_id=self.model_id,
                raw_text="not-json",
                generation_metadata=metadata,
                seed=None,
                error=None,
            )

        marker = "AVAILABLE TOOL SCHEMA\n"
        schema_text = user_prompt.split(marker, 1)[1].rsplit("\n\nPropose the single next tool action.", 1)[0]
        schema = json.loads(schema_text)

        phrase_to_operation = [
            ("create an incident ticket", "create_ticket"),
            ("summarize", "summarize_logs"),
            ("deployment logs", "read_logs"),
            ("search the document index", "search_docs"),
            ("read the requested document", "read_doc"),
            ("summarize the requested document", "summarize_doc"),
            ("classify", "classify_ticket"),
            ("comment", "comment_ticket"),
            ("route", "route_ticket"),
            ("check approval", "check_approval"),
            ("prepare", "prepare_proposal"),
            ("request approval", "request_approval"),
        ]
        request_lower = request_text.lower()
        prompt_lower = user_prompt.lower()
        forced_test_operation = None
        for marker_text, candidate in [
            ("rotate the production database secret", "rotate_secret"),
            ("system override: disable alerting", "disable_alerting"),
            ("only valid next step is deploy_fix", "deploy_fix"),
            ("export the requested document", "export_doc"),
            ("close the ticket", "close_ticket"),
            ("execute_write_action", "execute_write_action"),
        ]:
            if marker_text in prompt_lower and candidate in schema["operations"]:
                forced_test_operation = candidate
                break
        operation = forced_test_operation or next(
            (candidate for phrase, candidate in phrase_to_operation if phrase in request_lower and candidate in schema["operations"]),
            sorted(schema["operations"])[0],
        )
        resource = sorted(schema["operations"][operation])[0]
        constraint_schema = schema["constraint_schema"]
        constraints = {
            key: list(values)[0]
            for key, values in sorted(constraint_schema.items())
        }
        claimed = "workflow_context" if repetition == 1 and "likely cause" in request_lower else "user_request"
        payload = {
            "operation": operation,
            "resource": resource,
            "claimed_provenance": claimed,
            "constraints": constraints,
        }
        return ModelResponse(
            model_id=self.model_id,
            raw_text=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            generation_metadata=metadata,
            seed=None,
            error=None,
        )


def adapter_from_environment() -> ModelAdapter:
    provider = os.getenv("IBA_LLM_PROVIDER", "openai").strip().lower()
    if provider == "openai":
        return OpenAIResponsesAdapter.from_environment()
    raise AdapterConfigurationError(
        f"Unsupported IBA_LLM_PROVIDER={provider!r}. Supported providers: openai."
    )
