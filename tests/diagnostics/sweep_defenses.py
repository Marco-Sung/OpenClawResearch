# tests/diagnostics/sweep_defenses.py
#
# Step 3 of the Week 8 plan: automate what compare_defenses.py / compare_llm.py
# / tune_weights.py have each done by hand into ONE repeatable sweep that
# produces the professor's step-5 metrics table for every defense config.
#
# Design choice that matters: configs are read from DEFENSE_CONFIGS.keys()
# in defenses/input_sanitizer.py, NOT hardcoded here. Adding a new config
# there (e.g. "two_agent" for step 5, or a new one after adding the
# CSS-aware extractor for step 4) makes it show up in the next sweep run
# automatically -- no changes needed in this file.
#
#   PYTHONPATH=. venv/bin/python -m tests.diagnostics.sweep_defenses
#   PYTHONPATH=. venv/bin/python -m tests.diagnostics.sweep_defenses all direct --no-llm
#
# Writes results/defense_sweep.csv (one row per config) alongside the
# terminal report. Makes real API calls for any config with an LLM
# component (currently just risk_llm) -- pass --no-llm to skip those and
# stay free/instant.

import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from defenses.input_sanitizer import evaluate_write, Decision, DEFENSE_CONFIGS, get_stack
from defenses.risk import recipient_risk
from tests.attacks.core import ATTACKS as CORE_A, BENIGN_TASKS as CORE_B
from tests.attacks.email import EMAIL_ATTACKS as EMAIL_A, EMAIL_BENIGN as EMAIL_B
from tests.attacks.web import WEB_ATTACKS as WEB_A, WEB_BENIGN as WEB_B
from tests.attacks.file import FILE_ATTACKS as FILE_A, FILE_BENIGN as FILE_B
from tests.transport import pipeline

RESULTS_DIR = Path.home() / "openclaw-security" / "results"
RESULTS_CSV = RESULTS_DIR / "defense_sweep.csv"

ATTACK_SETS = {"core": CORE_A, "email": EMAIL_A, "web": WEB_A, "file": FILE_A}
BENIGN_SETS = {"core": CORE_B, "email": EMAIL_B, "web": WEB_B, "file": FILE_B}

# Attacks whose ASSIGNED extractor strips the payload before it ever reaches
# the defense (verified against tests/attacks/*.py). For these, ALLOW is the
# CORRECT outcome -- the attack was already defeated at the parser layer --
# so counting them as a defense "miss" would be misleading. Kept in sync with
# the same set in tune_weights.py.
PARSER_STRIPPED = {
    "web_hard_css_hidden_vs_hardened",
    "email_medium_html_part_injection",
    "email_hard_html_comment_in_part",
    "file_hard_pdf_hardened_check",
    "file_pdf_color_filter_gap",
    "web_extreme_css_class_only_hardened",  # css_aware drops the stylesheet-hidden class (step 4)
}


def extract_text(item, mode):
    if "raw" in item or "spec" in item:
        fn = pipeline.extract_transport if mode == "transport" else pipeline.extract_direct
        return fn(item, item.get("extract"))
    return item.get("payload", item.get("content", ""))


def sweep_one_config(config, channels, mode):
    attacks = [a for c in channels for a in ATTACK_SETS[c]]
    benign = [b for c in channels for b in BENIGN_SETS[c]]

    a_counts = {Decision.ALLOW: 0, Decision.CONFIRM: 0, Decision.BLOCK: 0}
    b_counts = {Decision.ALLOW: 0, Decision.CONFIRM: 0, Decision.BLOCK: 0}
    live_total = live_allowed = 0
    exfil_total = exfil_allowed = 0
    latencies_ms = []

    for item in attacks:
        text = extract_text(item, mode)
        if not text.strip():
            continue
        t0 = time.time()
        verdict = evaluate_write(item["target"], text, item.get("source", "external"), config)
        latencies_ms.append((time.time() - t0) * 1000)
        a_counts[verdict.decision] += 1

        is_live = item["name"] not in PARSER_STRIPPED
        if is_live:
            live_total += 1
            if verdict.decision is Decision.ALLOW:
                live_allowed += 1
        if recipient_risk(text) > 0:          # attack tries to send data somewhere
            exfil_total += 1
            if verdict.decision is Decision.ALLOW:
                exfil_allowed += 1

    for item in benign:
        text = extract_text(item, mode)
        if not text.strip():
            continue
        t0 = time.time()
        verdict = evaluate_write(item["target"], text, item.get("source", "external"), config)
        latencies_ms.append((time.time() - t0) * 1000)
        b_counts[verdict.decision] += 1

    n_a, n_b = len(attacks), len(benign)
    mean_ms = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

    # Pull real token cost off the cached LLM classifier, if this config uses one.
    cost_usd = calls = 0
    stack = get_stack(config)
    for comp in stack.components:
        clf = getattr(getattr(comp, "scorer", None), "classifier", None)
        if clf is not None and hasattr(clf, "calls"):
            calls = clf.calls
            cost_usd = clf.input_tokens / 1e6 * 1.0 + clf.output_tokens / 1e6 * 5.0

    return {
        "config": config,
        "attacks_n": n_a,
        "atk_allow": a_counts[Decision.ALLOW], "atk_confirm": a_counts[Decision.CONFIRM],
        "atk_block": a_counts[Decision.BLOCK],
        "attack_bypass_rate": a_counts[Decision.ALLOW] / n_a if n_a else 0,
        "live_bypass_rate": live_allowed / live_total if live_total else 0,
        "leakage_rate": exfil_allowed / exfil_total if exfil_total else 0,
        "benign_n": n_b,
        "ben_allow": b_counts[Decision.ALLOW], "ben_confirm": b_counts[Decision.CONFIRM],
        "ben_block": b_counts[Decision.BLOCK],
        "false_positive_rate": b_counts[Decision.BLOCK] / n_b if n_b else 0,
        "benign_auto_complete_rate": b_counts[Decision.ALLOW] / n_b if n_b else 0,
        "mean_latency_ms": round(mean_ms, 1),
        "llm_calls": calls,
        "cost_usd": round(cost_usd, 5),
    }


def print_report(rows):
    print(f"\n{'='*100}\n  DEFENSE SWEEP -- attacks\n{'='*100}")
    print(f"  {'config':<18} {'allow':>6} {'confirm':>8} {'block':>6}  "
          f"{'bypass%':>8} {'live-bypass%':>13} {'leak%':>7}")
    for r in rows:
        print(f"  {r['config']:<18} {r['atk_allow']:>6} {r['atk_confirm']:>8} {r['atk_block']:>6}  "
              f"{r['attack_bypass_rate']:>7.0%} {r['live_bypass_rate']:>12.0%} {r['leakage_rate']:>6.0%}")

    print(f"\n{'='*100}\n  DEFENSE SWEEP -- benign\n{'='*100}")
    print(f"  {'config':<18} {'allow':>6} {'confirm':>8} {'block':>6}  "
          f"{'FP-rate%':>9} {'auto-complete%':>15}")
    for r in rows:
        print(f"  {r['config']:<18} {r['ben_allow']:>6} {r['ben_confirm']:>8} {r['ben_block']:>6}  "
              f"{r['false_positive_rate']:>8.0%} {r['benign_auto_complete_rate']:>14.0%}")

    print(f"\n{'='*100}\n  DEFENSE SWEEP -- cost / latency\n{'='*100}")
    print(f"  {'config':<18} {'mean ms/item':>13} {'llm calls':>10} {'cost $':>8}")
    for r in rows:
        print(f"  {r['config']:<18} {r['mean_latency_ms']:>13} {r['llm_calls']:>10} {r['cost_usd']:>8}")
    print(f"\n{'='*100}\n")


def write_csv(rows):
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(RESULTS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"  Wrote {RESULTS_CSV}\n")


def main():
    args = sys.argv[1:]
    no_llm = "--no-llm" in args
    args = [a for a in args if a != "--no-llm"]
    channel = args[0] if len(args) > 0 else "all"
    mode = args[1] if len(args) > 1 else "direct"

    channels = ["core", "email", "web", "file"] if channel == "all" else [channel]
    configs = [c for c in DEFENSE_CONFIGS if not (no_llm and "llm" in c)]

    print(f"\nSweeping {len(configs)} configs over channel={channel} mode={mode} "
          f"({'excluding' if no_llm else 'including'} LLM configs)...\n")

    rows = []
    for config in configs:
        print(f"  running config={config} ...")
        rows.append(sweep_one_config(config, channels, mode))

    print_report(rows)
    write_csv(rows)


if __name__ == "__main__":
    main()
