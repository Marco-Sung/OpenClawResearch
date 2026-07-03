# OpenClaw Security Research

A red-team/blue-team testing framework for indirect prompt injection attacks against AI agents.

## Files

- `defenses/input_sanitizer.py` — Pydantic-based payload validator
- `tools/workspace_switcher.py` — Toggles between real and test workspaces
- `tests/research_runner.py` — Orchestrates before/after attack cycles
- `attack_log.json` — Results log (auto-generated)

## Setup

1. Clone this repo
2. Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install dependencies: `pip install pydantic`
4. Update paths in `workspace_switcher.py` and `research_runner.py` to point at your own `~/.openclaw/`
5. Run: `python tests/research_runner.py before`

## Research phases

**Phase 1:** Filesystem-level injection testing (current)
**Phase 2:** Real email channel injection (in progress)

