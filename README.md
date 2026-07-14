# OpenClaw Security Research

A red-team/blue-team testing framework for indirect prompt injection attacks against AI agents.

## Layout

```
defenses/
  input_sanitizer.py        # Pydantic-based payload validator (the defense under test)
tools/
  workspace_switcher.py     # Toggles openclaw between real and test workspaces
tests/
  research_runner.py        # CLI entry point: orchestrates before/after attack cycles
  attacks/                  # WHAT gets sent -- attack payload definitions
    core.py  email.py  web.py  file.py
  extraction/               # HOW raw content becomes text (direct mode, in-process)
    text.py                 #   html + email extractors
    files.py                #   file extractors (build from spec, then read back)
  transport/                # send over a REAL channel (transport mode)
    build.py deliver.py receive.py pipeline.py
    received_files.py       #   parse file bytes received over a channel
    server.py               #   stdlib web server for the web channel
  diagnostics/
    diff_attack.py          # compare one attack across direct vs transport
attack_log.json             # results log (auto-generated, git-ignored)
```

## Setup

1. Clone this repo
2. Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Update paths in `tools/workspace_switcher.py` and `tests/research_runner.py` to point at your own `~/.openclaw/`
5. Run: `python -m tests.research_runner before`

## Running

Run from the repo root so the `tests`, `defenses`, and `tools` packages resolve:

```
python -m tests.research_runner before  [channel] [mode]   # attacks, no sanitizer
python -m tests.research_runner after   [channel] [mode]   # attacks, with sanitizer
python -m tests.research_runner benign  [channel] [mode]   # false-positive check
python -m tests.research_runner compare [channel] [mode]   # per-strategy attribution
python -m tests.research_runner report                     # before/after table

  channel = core (default) / email / web / file / all
  mode    = direct (default) / transport
```

`transport` mode routes payloads over real channels first. Start the servers:

```
docker compose up -d                 # Mailpit (email channel)
python tests/transport/server.py     # web channel (leave running)
```

Diagnose a single attack across both modes:

```
python -m tests.diagnostics.diff_attack email email_charset_adjacent_trigger
```

## Research phases

**Phase 1:** Filesystem-level injection testing (current)
**Phase 2:** Real email channel injection (in progress)
