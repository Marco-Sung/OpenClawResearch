# tests/diagnostics/compare_defenses.py
#
# Side-by-side comparison of defense CONFIGS on the SAME inputs, so you can
# see the two research goals directly:
#
#   * benign-block rate  (false positives)  -- should go DOWN with risk scoring
#   * attack-bypass rate (attacks allowed)   -- should go DOWN with risk scoring
#
# It runs every attack and every benign task through each config using the
# rich evaluate_write() API (three-way allow/confirm/block). No files are
# written, nothing is sent, no servers/API key required -- it scores the
# extracted text in-process, so it is safe to run as often as you like.
#
#   python -m tests.diagnostics.compare_defenses
#   python -m tests.diagnostics.compare_defenses core      # one channel
#   python -m tests.diagnostics.compare_defenses all risk   # dump per-item risk detail
#
# A CONFIRM counts as "not a hard block" for benign (the human can approve it)
# and as "not a bypass" for attacks (the human can catch it), which is exactly
# why the three-way outcome matters.

import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from defenses.input_sanitizer import evaluate_write, Decision
from tests.attacks.core import ATTACKS as CORE_A, BENIGN_TASKS as CORE_B
from tests.attacks.email import EMAIL_ATTACKS as EMAIL_A, EMAIL_BENIGN as EMAIL_B
from tests.attacks.web import WEB_ATTACKS as WEB_A, WEB_BENIGN as WEB_B
from tests.attacks.file import FILE_ATTACKS as FILE_A, FILE_BENIGN as FILE_B
from tests.transport import pipeline

ATTACKS = {"core": CORE_A, "email": EMAIL_A, "web": WEB_A, "file": FILE_A}
BENIGN = {"core": CORE_B, "email": EMAIL_B, "web": WEB_B, "file": FILE_B}

CONFIGS = ["none", "regex", "full", "risk"]


def extract_text(item):
    """Extracted text an item would present to the sanitizer (direct mode),
    mirroring research_runner.produce_payload / the benign branch."""
    if "raw" in item or "spec" in item:
        return pipeline.extract_direct(item, item.get("extract"))
    if "payload" in item:
        return item["payload"]
    return item["content"]


def decide(item, config):
    text = extract_text(item)
    if not text.strip():
        return None  # extraction killed the payload before the sanitizer ran
    return evaluate_write(item["target"], text, item.get("source", "external"), config).decision


def tally(items, config):
    counts = {Decision.ALLOW: 0, Decision.CONFIRM: 0, Decision.BLOCK: 0, "empty": 0}
    for item in items:
        d = decide(item, config)
        counts["empty" if d is None else d] += 1
    return counts


def run(channel="all", detail=False):
    channels = ["core", "email", "web", "file"] if channel == "all" else [channel]
    attacks = [a for c in channels for a in ATTACKS[c]]
    benign = [b for c in channels for b in BENIGN[c]]

    print(f"\n{'='*74}")
    print(f"  DEFENSE COMPARISON  (channel={channel})   attacks={len(attacks)}  benign={len(benign)}")
    print(f"{'='*74}\n")

    # Goal 1: attacks. "Stopped" = blocked OR sent to confirm (not silently allowed).
    print(f"  ATTACKS  (goal: fewer BYPASSED)")
    print(f"  {'config':<10} {'block':>6} {'confirm':>8} {'BYPASS':>7} {'empty':>6}   bypass-rate")
    print(f"  {'-'*64}")
    for cfg in CONFIGS:
        c = tally(attacks, cfg)
        n = len(attacks)
        print(f"  {cfg:<10} {c[Decision.BLOCK]:>6} {c[Decision.CONFIRM]:>8} "
              f"{c[Decision.ALLOW]:>7} {c['empty']:>6}   {c[Decision.ALLOW]/n:>6.0%}")

    # Goal 2: benign. "Hard block" is the false positive we want to eliminate.
    print(f"\n  BENIGN  (goal: fewer BLOCKED)")
    print(f"  {'config':<10} {'allow':>6} {'confirm':>8} {'BLOCK(FP)':>10}   fp-rate")
    print(f"  {'-'*58}")
    for cfg in CONFIGS:
        c = tally(benign, cfg)
        n = len(benign)
        print(f"  {cfg:<10} {c[Decision.ALLOW]:>6} {c[Decision.CONFIRM]:>8} "
              f"{c[Decision.BLOCK]:>10}   {c[Decision.BLOCK]/n:>6.0%}")

    if detail:
        from defenses.risk import RiskScorer
        from defenses.input_sanitizer import WriteContext
        scorer = RiskScorer()
        print(f"\n  PER-ITEM RISK DETAIL (config=risk)")
        print(f"  {'-'*70}")
        for label, items in (("ATTACK", attacks), ("BENIGN", benign)):
            for item in items:
                text = extract_text(item)
                if not text.strip():
                    continue
                b = scorer.score(WriteContext(item["target"], text,
                                              item.get("source", "external")))
                print(f"  {label:<7} {item['name'][:38]:<38} "
                      f"{b.score:>5}  {b.decision.value:<7} <- {b.top_factor()}")

    print(f"\n{'='*74}\n")


if __name__ == "__main__":
    channel = sys.argv[1] if len(sys.argv) > 1 else "all"
    detail = len(sys.argv) > 2 and sys.argv[2] == "risk"
    run(channel, detail)
