# two_agent/ — Step 5: the sanitizer/executor/verifier architecture

The professor's recommendation: *"a two-agent architecture where one agent
sanitizes input and another executes tools."* This implements that, plus an
optional third verifier agent, as a **fully isolated system** — nothing in
`defenses/`, `tests/`, or `results/` imports or depends on anything here, and
this package doesn't import or modify anything of theirs either (it only
*reads* the existing attack/benign definitions and extraction functions).
Every command documented in `docs/commands.md` behaves identically whether
or not this folder exists.

## Why three different providers

Each stage can run on a **different model provider** (Anthropic / Gemini /
OpenAI). This isn't just "because we have three keys" — it's a deliberate
defense-in-depth argument: a prompt-injection technique that happens to work
against one provider's model doesn't automatically compromise every stage of
the pipeline. The sanitizer and executor seeing the world through different
models is itself part of the defense.

## The architecture

```
raw untrusted content
        |
        v
  SANITIZER (default: gemini)
   - sees the RAW content
   - outputs ONLY a neutral factual summary
   - any imperative instruction found gets flagged & dropped, never repeated
        |
        v  (sanitized summary ONLY -- executor never sees raw content)
  EXECUTOR (default: anthropic)
   - decides ALLOW / BLOCK for writing the summary to memory
        |
        v  (optional third stage)
  VERIFIER (default: openai)
   - independent auditor, sees raw content + summary + executor's decision
   - FAIL overrides the pipeline to BLOCK regardless of the executor
```

**Decision space is binary** (`ALLOW`/`BLOCK`), unlike the risk-scoring
configs' three-way `allow`/`confirm`/`block` — the professor's recommendation
didn't include a human-review middle state, so none was added here.

**Fail-safe on error:** if any stage's API call fails (network issue, bad
key), the pipeline defaults to `BLOCK` rather than silently passing content
through unsanitized.

## Setup

```bash
# 1. Install the two extra SDKs (not needed by the rest of the repo)
venv/bin/pip install -r requirements.txt

# 2. Add your Gemini and OpenAI keys to .env (Anthropic key should already be there)
#    Edit .env directly -- replace the placeholder lines with your real keys.
#    .env is git-ignored; verify with:
git check-ignore .env
```

## Commands

```bash
# Cheap smoke test first -- 1 attack + 1 benign item, ~6 API calls, verifies all 3 keys work
python -m two_agent.run_two_agent test

# Full run against one channel, three-agent mode (asks to confirm cost first)
python -m two_agent.run_two_agent core three

# Two-agent mode (no verifier), skip the cost prompt
python -m two_agent.run_two_agent web two --yes

# Every channel, three-agent mode
python -m two_agent.run_two_agent all three
```

Cost estimate is printed before any run starts. Results go to
`two_agent/results/two_agent_<channel>_<mode>.csv` — a separate folder from
the main `results/`, so this never mixes with or overwrites anything the
rest of the harness produces.

## Files

| File | What it is |
|---|---|
| `providers.py` | Provider-agnostic model callers (`call_model("gemini", ...)`). Model names are env-var overridable (`ANTHROPIC_MODEL`/`GEMINI_MODEL`/`OPENAI_MODEL`) since model catalogs change. |
| `pipeline.py` | The sanitizer → executor → verifier logic and prompts. |
| `run_two_agent.py` | CLI runner against your existing attack/benign sets (read-only reuse). |
| `results/` | This system's own output — separate from the main `results/` folder. |
