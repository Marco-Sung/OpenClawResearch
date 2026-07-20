# two_agent/hybrid.py
#
# Final paper contribution: combines the LLM-agent pipeline (pipeline.py)
# with the tuned risk_llm scoring system (defenses/risk.py, via
# defenses/input_sanitizer.py) into one three-way decision: ALLOW / CONFIRM
# / BLOCK.
#
# WHY combine them this way, not by re-prompting the agents for a 3-way
# answer themselves: the agent pipeline's sanitizer/executor prompts are
# already tested and verified (smoke-tested, run across hundreds of items).
# Redesigning them to natively output a third state would mean re-verifying
# that whole prompt/parsing surface. risk_llm, meanwhile, is ALREADY a
# calibrated three-way system -- it was empirically tuned (tune_weights.py:
# classifier weight 0.35, bands 0.40/0.70) specifically to know when to say
# "not sure" instead of guessing. So rather than teach the agents a new
# trick, this runs BOTH systems independently on the same content and takes
# the more severe of the two verdicts -- the exact "most severe wins" rule
# defenses/input_sanitizer.py's DefenseStack already uses internally. risk_llm
# is what introduces CONFIRM into the combined outcome, since the agent
# pipeline alone never produces it.
#
# On isolation: two_agent/ was built so nothing in defenses/ or tests/ ever
# imports it (existing commands stay unaffected either way -- confirmed
# earlier by grep). That guarantee was always one-directional. This file is
# the one place two_agent/ imports FROM defenses/ -- reusing evaluate_write()
# (a pure, side-effect-free function; it never writes anything) rather than
# re-implementing risk scoring a second time. That doesn't reintroduce any
# coupling the other direction: defenses/ and tests/ still know nothing
# about two_agent/, so every existing command is still completely unaffected.

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from two_agent.pipeline import run_pipeline, PipelineResult
from defenses.input_sanitizer import evaluate_write

_SEVERITY = {"ALLOW": 0, "CONFIRM": 1, "BLOCK": 2}


@dataclass
class HybridResult:
    final_decision: str          # ALLOW / CONFIRM / BLOCK -- the combined verdict
    agent_decision: str          # ALLOW / BLOCK -- from the agent pipeline alone
    risk_decision: str           # ALLOW / CONFIRM / BLOCK -- from risk_llm alone
    risk_score: float
    risk_reason: str
    combined_from: str           # "agent", "risk_llm", or "tie" -- which side determined the final call
    agent_result: PipelineResult

    # Pass-throughs so callers can treat a HybridResult like a PipelineResult
    # (same field names run_two_agent.py already reads off run_pipeline()).
    @property
    def sanitized_summary(self):
        return self.agent_result.sanitized_summary

    @property
    def executor_decision(self):
        return self.agent_result.executor_decision

    @property
    def executor_reason(self):
        return self.agent_result.executor_reason

    @property
    def verifier_audit(self):
        return self.agent_result.verifier_audit

    @property
    def verifier_reason(self):
        return self.agent_result.verifier_reason

    @property
    def overridden_by_verifier(self):
        return self.agent_result.overridden_by_verifier

    @property
    def fail_safe_triggered(self):
        return self.agent_result.fail_safe_triggered

    @property
    def stages(self):
        return self.agent_result.stages

    @property
    def total_cost_usd(self):
        # risk_llm's own call cost isn't tracked per-call the way the agent
        # stages are (evaluate_write doesn't return a ModelResponse) -- the
        # agent-side cost is the measurable total; risk_llm adds a roughly
        # comparable single-call cost on top, not separately metered here.
        return self.agent_result.total_cost_usd

    @property
    def total_latency_ms(self):
        return self.agent_result.total_latency_ms


def run_hybrid(
    raw_content: str,
    target_file: str,
    source: str = "external",
    sanitizer_provider: str = "gemini",
    executor_provider: str = "anthropic",
    verifier_provider: str = "openai",
) -> HybridResult:
    agent_result = run_pipeline(
        raw_content, target_file,
        sanitizer_provider=sanitizer_provider, executor_provider=executor_provider,
        verifier_provider=verifier_provider,
    )
    risk_verdict = evaluate_write(target_file, raw_content, source, config="risk_llm")
    risk_decision = risk_verdict.decision.value.upper()

    agent_sev = _SEVERITY[agent_result.final_decision]
    risk_sev = _SEVERITY[risk_decision]

    if agent_sev == risk_sev:
        final, combined_from = agent_result.final_decision, "tie"
    elif agent_sev > risk_sev:
        final, combined_from = agent_result.final_decision, "agent"
    else:
        final, combined_from = risk_decision, "risk_llm"

    return HybridResult(
        final_decision=final,
        agent_decision=agent_result.final_decision,
        risk_decision=risk_decision,
        risk_score=risk_verdict.score if risk_verdict.score is not None else 0.0,
        risk_reason=risk_verdict.reason,
        combined_from=combined_from,
        agent_result=agent_result,
    )
