# two_agent/providers.py
#
# Step 5: provider-agnostic model callers for the two/three-agent
# architecture. Deliberately isolated under two_agent/ (its own top-level
# package, sibling to defenses/ and tests/) so this system can be built,
# tested, and iterated on WITHOUT touching anything the rest of the harness
# depends on -- DEFENSE_CONFIGS, attack_log.json, results/, and every
# existing command keep behaving exactly as before.
#
# Each of the (up to) three agent roles can run on a DIFFERENT provider.
# That's a deliberate design choice, not just "because we have 3 keys":
# using heterogeneous models means a blind spot or jailbreak that works
# against one provider's model doesn't automatically compromise every
# stage of the pipeline -- a form of defense-in-depth at the model level.
#
# Model names are env-var overridable (ANTHROPIC_MODEL / GEMINI_MODEL /
# OPENAI_MODEL) because model catalogs change faster than this file does --
# don't hardcode a name and hope it ages well.

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

DEFAULT_MODELS = {
    "anthropic": os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5"),
    "gemini": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
    "openai": os.environ.get("OPENAI_MODEL", "gpt-5.5"),
}

# List price, USD per million tokens. VERIFY current pricing before quoting
# in the paper (same caveat as defenses/risk.py's classifier cost figures).
PRICING = {
    "anthropic": {"in": 1.0, "out": 5.0},     # claude-haiku-4-5
    "gemini": {"in": 0.3, "out": 2.5},        # gemini-2.5-flash (approx)
    "openai": {"in": 1.0, "out": 4.0},        # gpt-5.5 (approx)
}


@dataclass
class ModelResponse:
    text: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: float
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def cost_usd(self) -> float:
        p = PRICING.get(self.provider, {"in": 0, "out": 0})
        return self.input_tokens / 1e6 * p["in"] + self.output_tokens / 1e6 * p["out"]


def _call_anthropic(system: str, user: str, model: str) -> ModelResponse:
    import anthropic
    t0 = time.time()
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model, max_tokens=1024, system=system,
        messages=[{"role": "user", "content": user}],
    )
    return ModelResponse(
        text=resp.content[0].text, provider="anthropic", model=model,
        input_tokens=resp.usage.input_tokens, output_tokens=resp.usage.output_tokens,
        latency_ms=(time.time() - t0) * 1000,
    )


def _call_gemini(system: str, user: str, model: str) -> ModelResponse:
    from google import genai
    from google.genai import types
    t0 = time.time()
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    resp = client.models.generate_content(
        model=model, contents=user,
        config=types.GenerateContentConfig(system_instruction=system, max_output_tokens=1024),
    )
    usage = resp.usage_metadata
    return ModelResponse(
        text=resp.text or "", provider="gemini", model=model,
        input_tokens=usage.prompt_token_count or 0,
        output_tokens=usage.candidates_token_count or 0,
        latency_ms=(time.time() - t0) * 1000,
    )


def _call_openai(system: str, user: str, model: str) -> ModelResponse:
    import openai
    t0 = time.time()
    client = openai.OpenAI()
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        max_completion_tokens=1024,
    )
    return ModelResponse(
        text=resp.choices[0].message.content or "", provider="openai", model=model,
        input_tokens=resp.usage.prompt_tokens, output_tokens=resp.usage.completion_tokens,
        latency_ms=(time.time() - t0) * 1000,
    )


_CALLERS = {"anthropic": _call_anthropic, "gemini": _call_gemini, "openai": _call_openai}


_TRANSIENT_MARKERS = ("503", "UNAVAILABLE", "429", "rate_limit", "overloaded", "timeout")


def call_model(provider: str, system: str, user: str, model: Optional[str] = None,
                retries: int = 3) -> ModelResponse:
    """Uniform entry point: call_model('gemini', system_prompt, content).
    Never raises -- API/network failures come back as a ModelResponse with
    .error set and .ok False, so a pipeline stage can degrade gracefully
    (e.g. treat an unreachable sanitizer as 'block, couldn't verify safety')
    instead of crashing a whole benchmark run over one flaky call.

    Transient errors (503 "server busy", 429 rate-limit) are retried with
    exponential backoff -- these are about server load, not a bad request,
    so retrying is the correct response. A real error (bad key, malformed
    request) is NOT retried, since retrying that just wastes calls for the
    same guaranteed failure."""
    if provider not in _CALLERS:
        raise ValueError(f"Unknown provider '{provider}'. Choose from: {list(_CALLERS)}")
    model = model or DEFAULT_MODELS[provider]

    last_error = None
    for attempt in range(retries):
        try:
            return _CALLERS[provider](system, user, model)
        except Exception as e:
            last_error = str(e)
            is_transient = any(marker in last_error for marker in _TRANSIENT_MARKERS)
            if not is_transient or attempt == retries - 1:
                break
            time.sleep(2 ** attempt)   # 1s, 2s, 4s
    return ModelResponse(text="", provider=provider, model=model,
                          input_tokens=0, output_tokens=0, latency_ms=0.0, error=last_error)
