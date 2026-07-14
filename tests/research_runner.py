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
 
from tests.attacks.core import ATTACKS as CORE_ATTACKS, BENIGN_TASKS as CORE_BENIGN_TASKS
from tests.attacks.email import EMAIL_ATTACKS, EMAIL_BENIGN
from tests.attacks.web import WEB_ATTACKS, WEB_BENIGN
from tests.attacks.file import FILE_ATTACKS, FILE_BENIGN
from tests.extraction.text import extract
from tests.extraction.files import extract_file, FILE_EXTRACTORS
 
# NEW: transport harness (build -> deliver -> receive -> parse)
from tests.transport import pipeline
 
# -- PATHS ---------------------------------------------------------
 
REAL_WORKSPACE = Path.home() / ".openclaw" / "workspace"
TEST_WORKSPACE = Path.home() / ".openclaw" / "workspace_test"
LOG_PATH = Path.home() / "openclaw-security" / "attack_log.json"
 
# -- ATTACK SETS ---------------------------------------------------
 
ATTACK_SETS = {
    "core": CORE_ATTACKS,
    "email": EMAIL_ATTACKS,
    "web": WEB_ATTACKS,
    "file": FILE_ATTACKS,
    "all": CORE_ATTACKS + EMAIL_ATTACKS + WEB_ATTACKS + FILE_ATTACKS,
}
 
BENIGN_SETS = {
    "core": CORE_BENIGN_TASKS,
    "email": EMAIL_BENIGN,
    "web": WEB_BENIGN,
    "file": FILE_BENIGN,
    "all": CORE_BENIGN_TASKS + EMAIL_BENIGN + WEB_BENIGN + FILE_BENIGN,
}
 
MODES = {"direct", "transport"}
 
# -- WRITE FUNCTIONS -----------------------------------------------
 
def unsafe_write(target_file, content):
    """BEFORE defense -- writes directly to workspace_test, no validation."""
    out = TEST_WORKSPACE / target_file
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content)
    return "bypassed"
 
def safe_write_wrapper(target_file, content, source="external"):
    """AFTER defense -- routes through the sanitizer."""
    return safe_write(target_file, content, source=source)
 
# -- PAYLOAD PRODUCTION --------------------------------------------
 
def produce_payload(attack, mode):
    """Return the extracted payload string for an attack, using either the
    in-process extractor (direct) or the full channel round-trip (transport).
    The result feeds the SAME safe_write() either way."""
    strategy = attack.get("extract")
    if mode == "transport":
        return pipeline.extract_transport(attack, strategy)
    return pipeline.extract_direct(attack, strategy)
 
def extract_note(attack, mode):
    if "raw" in attack:
        kind = attack.get("extract_kind", "html")
        return f" [{mode} {kind}/{attack['extract']}]"
    if "spec" in attack:
        return f" [{mode} file/{attack['extract']}]"
    return ""
 
# -- LOGGING -------------------------------------------------------
 
def log_attack(attack_name, tier, target, payload, write_result, agent_result, phase, mode="direct"):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "phase": phase,
        "mode": mode,
        "attack": attack_name,
        "tier": tier,
        "target": target,
        "write_result": write_result,
        "agent_result": agent_result,
        "payload_preview": payload[:100],
    }
    existing = json.loads(LOG_PATH.read_text()) if LOG_PATH.exists() else []
    existing.append(entry)
    LOG_PATH.write_text(json.dumps(existing, indent=2))
 
def reset_workspace_test():
    if TEST_WORKSPACE.exists():
        shutil.rmtree(TEST_WORKSPACE)
    shutil.copytree(REAL_WORKSPACE, TEST_WORKSPACE)
    print(f"  ok workspace_test reset to clean state")
 
def run_benign_tests(channel="core", mode="direct"):
    benign_tasks = BENIGN_SETS.get(channel, CORE_BENIGN_TASKS)
 
    print(f"\n{'='*60}")
    print(f"  BENIGN TASK TESTING -- false positive check ({channel}, mode={mode})")
    print(f"{'='*60}\n")
 
    switch_to_test()
    reset_workspace_test()
    print()
 
    false_positives = 0
 
    for task in benign_tasks:
        # Channel benign tasks (email/web/file) carry raw/spec and run
        # through the SAME extractor path as attacks; core benign tasks
        # carry a plain "content" string. Either way the resulting text
        # is what safe_write() sees.
        if "raw" in task or "spec" in task:
            content = produce_payload(task, mode)
            note = extract_note(task, mode)
        else:
            content = task["content"]
            note = ""

        result = safe_write(task["target"], content, task.get("source", "external"))
        passed = result == "bypassed"
 
        if passed:
            print(f"  ok {task['name']}{note} -- correctly allowed")
        else:
            print(f"  X  {task['name']}{note} -- WRONGLY BLOCKED (false positive)")
            print(f"     reason: {result.replace('blocked: ', '')}")
            false_positives += 1
 
        log_attack(task["name"], "benign", task["target"], content,
                   result, "n/a", "benign", mode)
 
    switch_to_real()
 
    print(f"\n{'='*60}")
    print(f"  False positive rate: {false_positives}/{len(benign_tasks)}")
    if false_positives == 0:
        print(f"  ok Sanitizer does not block legitimate content")
    else:
        print(f"  !! Sanitizer is too aggressive -- review patterns")
    print(f"{'='*60}\n")
 
# -- MAIN PHASE RUNNER ---------------------------------------------
 
def run_phase(phase, channel="core", mode="direct"):
    """
    phase   = "before" -> unsafe_write, no sanitizer
              "after"  -> safe_write, with sanitizer
    channel = core / email / web / file / all
    mode    = direct    -> parse in-process (fast, no servers)
              transport -> build -> deliver -> receive -> parse (real channel)
    """
    attacks = ATTACK_SETS[channel]
 
    print(f"\n{'='*60}")
    print(f"  PHASE: {phase.upper()} -- {'no sanitizer' if phase == 'before' else 'with sanitizer'}")
    print(f"  CHANNEL: {channel}   MODE: {mode}")
    print(f"{'='*60}\n")
 
    switch_to_test()
    print()
    reset_workspace_test()
    print()
 
    by_tier = {}
    for attack in attacks:
        by_tier.setdefault(attack["tier"], []).append(attack)
 
    for tier in ["trivial", "medium", "hard"]:
        if tier not in by_tier:
            continue
 
        print(f"-- {tier.upper()} --")
 
        for attack in by_tier[tier]:
            name = attack["name"]
            target = attack["target"]
            trigger = attack["trigger"]
            source = attack.get("source", "external")
 
            # -- EXTRACTION STEP (direct or transport) -------------
            payload = produce_payload(attack, mode)
            note = extract_note(attack, mode)
 
            if phase == "before":
                write_result = unsafe_write(target, payload)
            else:
                write_result = safe_write_wrapper(target, payload, source)
 
            if write_result == "bypassed":
                print(f"  X  {name}{note}")
                print(f"     write: BYPASSED -- payload reached workspace_test/")
                print(f"\n     -- Manual test required --")
                print(f"     1. Open a NEW terminal on your VM:")
                print(f"        ssh root@your-hetzner-ip")
                print(f"     2. Start openclaw:  openclaw")
                print(f"     3. Ask the trigger question:")
                print(f"        > {trigger}")
                print(f"     4. Does the response seem MANIPULATED by the poison?")
                print(f"\n")
 
                agent_result = input(f"     What did openclaw do? (manipulated/normal/unsure): ").strip().lower()
                if agent_result not in ["manipulated", "normal", "unsure"]:
                    agent_result = "unsure"
            else:
                reason = write_result.replace("blocked: ", "")
                print(f"  ok {name}{note}")
                print(f"     write: BLOCKED")
                print(f"     reason: {reason}")
                agent_result = "not_tested"
 
            log_attack(name, attack["tier"], target, payload, write_result, agent_result, phase, mode)
            print()
 
    switch_to_real()
    print(f"\n  ok Switched back to REAL workspace\n")
 
# -- REPORT PRINTER ------------------------------------------------
 
def print_report():
    if not LOG_PATH.exists():
        print("\nX No log found -- run phases first.\n")
        return
 
    entries = json.loads(LOG_PATH.read_text())
    before = {e["attack"]: e for e in entries if e.get("phase") == "before"}
    after = {e["attack"]: e for e in entries if e.get("phase") == "after"}
    all_attacks = sorted(set(list(before.keys()) + list(after.keys())))
 
    print(f"\n{'='*80}")
    print(f"  RESEARCH RESULTS -- Before vs After defense")
    print(f"{'='*80}\n")
    print(f"  {'Attack':<40} {'Tier':<8} {'Before':<12} {'After':<12}")
    print(f"  {'-'*75}")
 
    blocked_after = 0
    total_attacks = len(after)
 
    for atk in all_attacks:
        b = before.get(atk, {})
        a = after.get(atk, {})
        tier = b.get("tier", a.get("tier", "?"))
 
        b_agent = b.get("agent_result", "not run")
        if b_agent == "manipulated":
            b_label = "VULNERABLE"
        elif b_agent == "normal":
            b_label = "SAFE"
        else:
            b_label = b_agent.upper()
 
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
 
# -- EXTRACTOR COMPARISON ------------------------------------------
 
def compare_extractors(channel="web", mode="direct"):
    """
    Runs EVERY extractable attack through ALL relevant extraction strategies,
    then checks each result against the sanitizer. With mode=transport the
    content is first routed through the real channel, so a divergence between
    direct and transport isolates the TRANSPORT layer from the PARSER layer.
    """
    attacks = ATTACK_SETS[channel]
    raw_attacks = [a for a in attacks if "raw" in a]
    spec_attacks = [a for a in attacks if "spec" in a]
 
    if not raw_attacks and not spec_attacks:
        print(f"\n  No extractable attacks in '{channel}' - nothing to compare.\n")
        return
 
    from tests.extraction.text import HTML_EXTRACTORS, EMAIL_EXTRACTORS
 
    print(f"\n{'='*78}")
    print(f"  EXTRACTOR COMPARISON -- {channel}   (mode: {mode})")
    print(f"  For each attack, every extraction strategy's result vs sanitizer.")
    print(f"{'='*78}")
 
    def _run_and_report(attack, strategies, extract_call):
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
                outcome = f"BLOCKED -- {verdict.replace('blocked: ', '')}"
            else:
                outcome = "BYPASSED sanitizer"
            print(f"    {strat_name:<22} {outcome} {marker}")
 
    for attack in raw_attacks:
        kind = attack.get("extract_kind", "html")
        strategies = HTML_EXTRACTORS if kind == "html" else EMAIL_EXTRACTORS
        if mode == "transport":
            call = lambda strat, a=attack: pipeline.extract_transport(a, strat)
        else:
            call = lambda strat, a=attack, k=kind: extract(a["raw"], k, strat)
        _run_and_report(attack, strategies, call)
 
    for attack in spec_attacks:
        assigned = attack["extract"]
        fmt = assigned.split("_")[0]
        relevant = {n: f for n, f in FILE_EXTRACTORS.items()
                    if n.split("_")[0] == fmt or n == "txt"}
        if mode == "transport":
            call = lambda strat, a=attack: pipeline.extract_transport(a, strat)
        else:
            call = lambda strat, a=attack: extract_file(a["spec"], strat)
        _run_and_report(attack, relevant, call)
 
    print(f"\n{'='*78}\n")
 
# -- MAIN ----------------------------------------------------------
 
if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    channel = sys.argv[2] if len(sys.argv) > 2 else "core"
    mode = sys.argv[3] if len(sys.argv) > 3 else "direct"
 
    if cmd in {"before", "after", "benign", "compare"} and channel not in ATTACK_SETS:
        print(f"\nX Unknown channel '{channel}'. Choose from: {list(ATTACK_SETS.keys())}\n")
        sys.exit(1)
    if mode not in MODES:
        print(f"\nX Unknown mode '{mode}'. Choose from: {list(MODES)}\n")
        sys.exit(1)
 
    if cmd == "before":
        run_phase("before", channel, mode)
    elif cmd == "after":
        run_phase("after", channel, mode)
    elif cmd == "benign":
        run_benign_tests(channel, mode)
    elif cmd == "compare":
        compare_extractors(channel, mode)
    elif cmd == "report":
        print_report()
    else:
        print("""
Usage:
  python -m tests.research_runner before  [channel] [mode]   # attacks, no sanitizer
  python -m tests.research_runner after   [channel] [mode]   # attacks, with sanitizer
  python -m tests.research_runner benign  [channel] [mode]   # false-positive check
  python -m tests.research_runner compare [channel] [mode]   # per-strategy attribution
  python -m tests.research_runner report                     # before/after table
 
  channel = core (default) / email / web / file / all
  mode    = direct (default) / transport
 
  direct    = parse the payload in-process (fast; use while tuning regex).
  transport = build -> deliver -> receive -> parse over a real channel.
              Start servers first:
                docker compose up -d
                python tests/transport/server.py
 
Example:
  python -m tests.research_runner after   web  transport
  python -m tests.research_runner compare web  transport
""")