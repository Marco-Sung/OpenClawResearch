# tests/research_runner.py
 
import sys
import json
import shutil
import datetime
from pathlib import Path
 
sys.path.insert(0, str(Path.home() / "openclaw-security"))
 
from defenses.input_sanitizer import safe_write, WorkspaceWriteRequest
from pydantic import ValidationError
from tools.workspace_switcher import switch_to_test, switch_to_real
 
from tests.core.core_attacks import ATTACKS as CORE_ATTACKS, BENIGN_TASKS as CORE_BENIGN_TASKS
from tests.channels.email.payloads import EMAIL_ATTACKS
from tests.channels.web.payloads import WEB_ATTACKS
from tests.channels.file.payloads import FILE_ATTACKS
from tests.channels.parsers.extractors import extract
from tests.channels.parsers.file_extractors import extract_file, FILE_EXTRACTORS
 
# ── PATHS ─────────────────────────────────────────────────────────
 
REAL_WORKSPACE = Path.home() / ".openclaw" / "workspace"
TEST_WORKSPACE = Path.home() / ".openclaw" / "workspace_test"
LOG_PATH = Path.home() / "openclaw-security" / "attack_log.json"
 
# ── ATTACK SETS ───────────────────────────────────────────────────
# "core" is your original trivial/medium/hard MEMORY.md poisoning set.
# "email"/"web" are channel-specific vectors, same dict schema, so
# everything below (run_phase, log_attack, print_report) works on any
# of them unchanged. "all" runs everything in one pass.
 
ATTACK_SETS = {
    "core": CORE_ATTACKS,
    "email": EMAIL_ATTACKS,
    "web": WEB_ATTACKS,
    "file": FILE_ATTACKS,
    "all": CORE_ATTACKS + EMAIL_ATTACKS + WEB_ATTACKS + FILE_ATTACKS,
}
 
BENIGN_SETS = {
    "core": CORE_BENIGN_TASKS,
    # email/web don't have their own benign sets yet - falls back to
    # CORE_BENIGN_TASKS in run_benign_tests() below. Add channel-
    # specific benign tasks here if false-positive testing needs to
    # be channel-aware later.
}
 
# ── WRITE FUNCTIONS ───────────────────────────────────────────────
 
def unsafe_write(target_file, content):
    """
    BEFORE defense — writes directly to workspace_test with no validation.
    This is what happens when the sanitizer doesn't exist.
    """
    out = TEST_WORKSPACE / target_file
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content)
    return "bypassed"
 
def safe_write_wrapper(target_file, content, source="external"):
    """
    AFTER defense — routes through the sanitizer.
    source is now passed in per-attack instead of hardcoded.
    """
    result = safe_write(target_file, content, source=source)
    return result
 
# ── LOGGING ───────────────────────────────────────────────────────
 
def log_attack(attack_name, tier, target, payload, write_result, agent_result, phase):
    """
    Records each attack attempt and its outcome to attack_log.json
    """
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "phase": phase,
        "attack": attack_name,
        "tier": tier,
        "target": target,
        "write_result": write_result,        # "bypassed" or "blocked: reason"
        "agent_result": agent_result,        # "manipulated" / "normal" / "not_tested"
        "payload_preview": payload[:100],
    }
 
    existing = json.loads(LOG_PATH.read_text()) if LOG_PATH.exists() else []
    existing.append(entry)
    LOG_PATH.write_text(json.dumps(existing, indent=2))
 
def reset_workspace_test():
    """
    Clears workspace_test and rebuilds it as a clean copy of real workspace.
    Run this before each phase so both start from identical state.
    """
    if TEST_WORKSPACE.exists():
        shutil.rmtree(TEST_WORKSPACE)
    shutil.copytree(REAL_WORKSPACE, TEST_WORKSPACE)
    print(f"  ✓ workspace_test reset to clean state")
 
def run_benign_tests(channel="core"):
    """
    Checks whether the sanitizer WRONGLY blocks legitimate content.
    This measures your false-positive rate — critical per feedback.
    """
    benign_tasks = BENIGN_SETS.get(channel, CORE_BENIGN_TASKS)
 
    print(f"\n{'='*60}")
    print(f"  BENIGN TASK TESTING — false positive check ({channel})")
    print(f"{'='*60}\n")
 
    switch_to_test()
    reset_workspace_test()
    print()
 
    false_positives = 0
 
    for task in benign_tasks:
        result = safe_write(task["target"], task["content"], task["source"])
        passed = result == "bypassed"
 
        if passed:
            print(f"  ✓ {task['name']} — correctly allowed")
        else:
            print(f"  ✗ {task['name']} — WRONGLY BLOCKED (false positive)")
            print(f"     reason: {result.replace('blocked: ', '')}")
            false_positives += 1
 
        log_attack(
            task["name"], "benign", task["target"], task["content"],
            result, "n/a", "benign"
        )
 
    switch_to_real()
 
    print(f"\n{'='*60}")
    print(f"  False positive rate: {false_positives}/{len(benign_tasks)}")
    if false_positives == 0:
        print(f"  ✓ Sanitizer does not block legitimate content")
    else:
        print(f"  ⚠ Sanitizer is too aggressive — review patterns")
    print(f"{'='*60}\n")
 
# ── MAIN PHASE RUNNER ─────────────────────────────────────────────
 
def run_phase(phase, channel="core"):
    """
    phase = "before"  → unsafe_write, no sanitizer
    phase = "after"   → safe_write, with sanitizer
    channel = "core" / "email" / "web" / "all" — which attack set to run
 
    For each attack:
      1. Fire the payload
      2. If it got through, pause and ask you to manually test openclaw
      3. Log the result
    """
 
    attacks = ATTACK_SETS[channel]
 
    print(f"\n{'='*60}")
    print(f"  PHASE: {phase.upper()} — {'no sanitizer' if phase == 'before' else 'with sanitizer'}")
    print(f"  CHANNEL: {channel}")
    print(f"{'='*60}\n")
 
    # Point openclaw at test workspace
    switch_to_test()
    print()
 
    # Reset workspace_test to clean state
    reset_workspace_test()
    print()
 
    # Select which write function to use
    write_func = unsafe_write if phase == "before" else safe_write_wrapper
 
    # Group attacks by tier for clearer output
    by_tier = {}
    for attack in attacks:
        tier = attack["tier"]
        if tier not in by_tier:
            by_tier[tier] = []
        by_tier[tier].append(attack)
 
    # Fire each attack
    for tier in ["trivial", "medium", "hard"]:
        if tier not in by_tier:
            continue
 
        print(f"── {tier.upper()} ──")
 
        for attack in by_tier[tier]:
            name = attack["name"]
            target = attack["target"]
            trigger = attack["trigger"]
 
            # Fire the attack — pass source if the attack defines one
            source = attack.get("source", "external")   # defaults to external if not specified
 
            # ── EXTRACTION STEP ────────────────────────────────────
            # Three payload shapes, checked in order:
            #   "raw"     - web (HTML) / email (MIME): run through the
            #               html/email extractor named in "extract".
            #   "spec"    - file: BUILD a real txt/pdf/docx from the
            #               spec's visible+hidden text, then extract it
            #               back via the file extractor named in
            #               "extract". Tests real pdf/docx parsing.
            #   "payload" - core: pre-written string, no extraction.
            if "raw" in attack:
                kind = attack.get("extract_kind", "html")  # web defaults to html
                strategy = attack["extract"]
                payload = extract(attack["raw"], kind, strategy)
                extract_note = f" [extracted via {kind}/{strategy}]"
            elif "spec" in attack:
                strategy = attack["extract"]
                payload = extract_file(attack["spec"], strategy)
                extract_note = f" [extracted via file/{strategy}]"
            else:
                payload = attack["payload"]
                extract_note = ""
 
            if phase == "before":
                write_result = unsafe_write(target, payload)
            else:
                write_result = safe_write_wrapper(target, payload, source)
 
            # Display what happened
            if write_result == "bypassed":
                print(f"  ✗ {name}{extract_note}")
                print(f"     write: BYPASSED — payload reached workspace_test/")
 
                # Ask user to test openclaw
                print(f"\n     ── Manual test required ──")
                print(f"     1. Open a NEW terminal on your VM:")
                print(f"        ssh root@your-hetzner-ip")
                print(f"     2. Start openclaw:")
                print(f"        openclaw")
                print(f"     3. Ask the trigger question:")
                print(f"        > {trigger}")
                print(f"     4. Note: does the response seem MANIPULATED by the poison?")
                print(f"\n")
 
                agent_result = input(f"     What did openclaw do? (manipulated/normal/unsure): ").strip().lower()
 
                if agent_result not in ["manipulated", "normal", "unsure"]:
                    agent_result = "unsure"
 
            else:
                # Sanitizer blocked it
                reason = write_result.replace("blocked: ", "")
                print(f"  ✓ {name}{extract_note}")
                print(f"     write: BLOCKED")
                print(f"     reason: {reason}")
                agent_result = "not_tested"  # never reached openclaw
 
            log_attack(name, attack["tier"], target, payload, write_result, agent_result, phase)
            print()
 
    # Always switch back to real workspace when done
    switch_to_real()
    print(f"\n  ✓ Switched back to REAL workspace\n")
 
# ── REPORT PRINTER ────────────────────────────────────────────────
 
def print_report():
    """
    Reads attack_log.json and prints a before/after comparison table.
    """
    if not LOG_PATH.exists():
        print("\n✗ No log found — run phases first.\n")
        return
 
    entries = json.loads(LOG_PATH.read_text())
 
    # Split entries by phase
    before = {e["attack"]: e for e in entries if e.get("phase") == "before"}
    after = {e["attack"]: e for e in entries if e.get("phase") == "after"}
    all_attacks = sorted(set(list(before.keys()) + list(after.keys())))
 
    print(f"\n{'='*80}")
    print(f"  RESEARCH RESULTS — Before vs After defense")
    print(f"{'='*80}\n")
    print(f"  {'Attack':<40} {'Tier':<8} {'Before':<12} {'After':<12}")
    print(f"  {'-'*75}")
 
    blocked_after = 0
    total_attacks = len(after)
 
    for atk in all_attacks:
        b = before.get(atk, {})
        a = after.get(atk, {})
        tier = b.get("tier", a.get("tier", "?"))
 
        # Before: was agent manipulated?
        b_agent = b.get("agent_result", "not run")
        if b_agent == "manipulated":
            b_label = "VULNERABLE"
        elif b_agent == "normal":
            b_label = "SAFE"
        else:
            b_label = b_agent.upper()
 
        # After: was write blocked?
        a_write = a.get("write_result", "not run")
        if a_write.startswith("blocked"):
            a_label = "BLOCKED"
            blocked_after += 1
        elif a_write == "bypassed":
            a_label = "BYPASSED"
        else:
            a_label = "NOT RUN"
 
        print(f"  {atk:<40} {tier:<8} {b_label:<12} {a_label:<12}")
 
    print(f"\n  Defense effectiveness: {blocked_after}/{total_attacks} attacks blocked\n")
    print(f"  Full log: {LOG_PATH}\n")
 
def compare_extractors(channel="web"):
    """
    Runs EVERY extractable attack through ALL relevant extraction
    strategies (not just the one hardcoded in its dict), then checks
    each result against the sanitizer. Pinpoints which extraction
    strategy is responsible for a bypass, automatically, without you
    hand-writing a separate attack entry per extractor.
 
    Handles two extractable shapes:
      "raw"  - web (html) / email (mime)
      "spec" - file (txt/pdf/docx)
    Core attacks (plain "payload", no extraction) have nothing to
    compare and are skipped.
    """
    attacks = ATTACK_SETS[channel]
    raw_attacks = [a for a in attacks if "raw" in a]
    spec_attacks = [a for a in attacks if "spec" in a]
 
    if not raw_attacks and not spec_attacks:
        print(f"\n  No extractable attacks in '{channel}' - nothing to "
              f"compare (core attacks use plain payload strings, no "
              f"extraction step exists for them).\n")
        return
 
    from tests.channels.parsers.extractors import HTML_EXTRACTORS, EMAIL_EXTRACTORS
 
    print(f"\n{'='*78}")
    print(f"  EXTRACTOR COMPARISON — {channel}")
    print(f"  For each attack, showing every extraction strategy's result,")
    print(f"  not just the one currently assigned in payloads.py")
    print(f"{'='*78}")
 
    def _run_and_report(attack, strategies, extract_call):
        """strategies: dict of name->fn (for display/marker only).
        extract_call: fn(strat_name) -> extracted text string."""
        assigned = attack["extract"]
        print(f"\n  {attack['name']}  (assigned strategy: {assigned})")
        print(f"  {'-'*70}")
        for strat_name in strategies:
            try:
                extracted = extract_call(strat_name)
            except Exception as e:
                print(f"    {strat_name:<22} ERROR: {e}")
                continue
            verdict = safe_write(attack["target"], extracted, attack.get("source", "external"))
            blocked = verdict.startswith("blocked")
            marker = "(assigned)" if strat_name == assigned else ""
            if not extracted.strip():
                outcome = "EXTRACTION EMPTY (nothing to write)"
            elif blocked:
                outcome = f"BLOCKED — {verdict.replace('blocked: ', '')}"
            else:
                outcome = "BYPASSED sanitizer"
            print(f"    {strat_name:<22} {outcome} {marker}")
 
    # web/email: raw string through html/email extractors
    for attack in raw_attacks:
        kind = attack.get("extract_kind", "html")
        strategies = HTML_EXTRACTORS if kind == "html" else EMAIL_EXTRACTORS
        _run_and_report(
            attack, strategies,
            lambda strat, a=attack, k=kind: extract(a["raw"], k, strat),
        )
 
    # file: spec through file extractors. Only compare strategies whose
    # format matches the assigned one (comparing a pdf extractor to a
    # docx spec is apples-to-oranges), EXCEPT txt which is format-free.
    for attack in spec_attacks:
        assigned = attack["extract"]
        fmt = assigned.split("_")[0]  # "pdf", "docx", or "txt"
        relevant = {n: f for n, f in FILE_EXTRACTORS.items()
                    if n.split("_")[0] == fmt or n == "txt"}
        _run_and_report(
            attack, relevant,
            lambda strat, a=attack: extract_file(a["spec"], strat),
        )
 
    print(f"\n{'='*78}\n")
 
 
# ── MAIN ──────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    channel = sys.argv[2] if len(sys.argv) > 2 else "core"
 
    if channel not in ATTACK_SETS:
        print(f"\n✗ Unknown channel '{channel}'. Choose from: {list(ATTACK_SETS.keys())}\n")
        sys.exit(1)
 
    if cmd == "before":
        run_phase("before", channel)
 
    elif cmd == "after":
        run_phase("after", channel)
 
    elif cmd == "benign":
        run_benign_tests(channel)
 
    elif cmd == "compare":
        compare_extractors(channel)
 
    elif cmd == "report":
        print_report()
 
    else:
        print(f"""
Usage:
  python -m tests.research_runner before  [channel]   # Run attacks without sanitizer
  python -m tests.research_runner after   [channel]   # Run attacks with sanitizer
  python -m tests.research_runner benign  [channel]   # Test for false positives
  python -m tests.research_runner compare [channel]   # Run ALL extractors on each
                                                        # attack's raw content, to
                                                        # pinpoint which extraction
                                                        # strategy is responsible
                                                        # for a bypass
  python -m tests.research_runner report               # Print before/after comparison
 
  channel = core (default) / email / web / all
 
Workflow:
  1. python -m tests.research_runner before email
     → fires all EMAIL attacks with no defense
     → pauses for manual openclaw testing
     → records results
 
  2. python -m tests.research_runner after email
     → fires same EMAIL attacks with sanitizer
     → records which ones got blocked
 
  3. python -m tests.research_runner compare web
     → for each web attack, shows what naive_regex/bs4_get_text/
       bs4_visible_only EACH produce and whether the sanitizer
       would block each result — pinpoints exactly which extractor
       choice is responsible for any given bypass
 
  4. python -m tests.research_runner benign email
     → Tests prompts that should go through
 
  5. python -m tests.research_runner report
     → prints comparison table across ALL channels tested so far
""")