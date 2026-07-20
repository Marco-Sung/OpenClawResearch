# two_agent/run_two_agent.py
#
# Step 5 CLI: runs the sanitizer -> executor (-> verifier) pipeline against
# your EXISTING attack/benign sets. Read-only reuse of tests.attacks.* and
# tests.extraction.* -- this file imports them but never modifies them, and
# writes its own results to two_agent/results/, never touching the main
# results/ folder or attack_log.json. Every other command in this repo
# behaves identically whether or not you ever run this file.
#
# NOTE: this pipeline's decision space is {ALLOW, BLOCK} -- binary, unlike
# the risk-scoring configs' {allow, confirm, block}. The professor's
# recommendation was "one agent sanitizes, another executes" with no
# mention of a human-review middle state, so that's what's implemented.
#
#   python -m two_agent.run_two_agent test                 # cheap smoke test (~6 calls)
#   python -m two_agent.run_two_agent core two              # 2-agent, core channel
#   python -m two_agent.run_two_agent all three              # 3-agent, everything
#   python -m two_agent.run_two_agent web three --yes         # skip the cost confirmation

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from two_agent.pipeline import run_pipeline
from two_agent.hybrid import run_hybrid
from tests.attacks.core import ATTACKS as CORE_A, BENIGN_TASKS as CORE_B
from tests.attacks.email import EMAIL_ATTACKS as EMAIL_A, EMAIL_BENIGN as EMAIL_B
from tests.attacks.web import WEB_ATTACKS as WEB_A, WEB_BENIGN as WEB_B
from tests.attacks.file import FILE_ATTACKS as FILE_A, FILE_BENIGN as FILE_B
from tests.transport import pipeline as extract_pipeline

RESULTS_DIR = Path(__file__).resolve().parent / "results"

ATTACK_SETS = {"core": CORE_A, "email": EMAIL_A, "web": WEB_A, "file": FILE_A,
               "all": CORE_A + EMAIL_A + WEB_A + FILE_A}
BENIGN_SETS = {"core": CORE_B, "email": EMAIL_B, "web": WEB_B, "file": FILE_B,
               "all": CORE_B + EMAIL_B + WEB_B + FILE_B}


def extract_text(item):
    if "raw" in item or "spec" in item:
        return extract_pipeline.extract_direct(item, item.get("extract"))
    return item.get("payload", item.get("content", ""))


def run_item(item, mode):
    text = extract_text(item)
    if not text.strip():
        return None
    if mode == "hybrid":
        return run_hybrid(text, item["target"], item.get("source", "external"),
                           sanitizer_provider="gemini", executor_provider="anthropic",
                           verifier_provider="openai")
    verifier = "openai" if mode == "three" else None
    return run_pipeline(text, item["target"],
                         sanitizer_provider="gemini", executor_provider="anthropic",
                         verifier_provider=verifier)


def smoke_test():
    print("\n" + "=" * 78)
    print("  SMOKE TEST -- one attack, one benign item, three-agent mode (~6 API calls)")
    print("=" * 78)
    for label, item in [("ATTACK", CORE_A[0]), ("BENIGN", CORE_B[0])]:
        print(f"\n--- {label}: {item['name']} ---")
        r = run_item(item, "three")
        print(f"  sanitized summary: {r.sanitized_summary[:200]!r}")
        print(f"  executor: {r.executor_decision} -- {r.executor_reason}")
        if r.verifier_audit:
            print(f"  verifier: {r.verifier_audit} -- {r.verifier_reason}")
        print(f"  FINAL: {r.final_decision}"
              f"{'  (overridden by verifier)' if r.overridden_by_verifier else ''}")
        print(f"  cost=${r.total_cost_usd:.5f}  latency={r.total_latency_ms:.0f}ms")
        for s in r.stages:
            if not s.ok:
                print(f"  !! {s.provider} FAILED: {s.error}")
    print("\n" + "=" * 78 + "\n")


def full_run(channel, mode, skip_confirm):
    attacks = ATTACK_SETS[channel]
    benign = BENIGN_SETS[channel]
    calls_per_item = {"two": 2, "three": 3, "hybrid": 4}[mode]   # hybrid = 3 agent calls + 1 risk_llm call
    n_items = len(attacks) + len(benign)
    est_calls = n_items * calls_per_item

    providers = {"two": "gemini/anthropic", "three": "gemini/anthropic/openai",
                 "hybrid": "gemini/anthropic/openai + risk_llm (anthropic)"}[mode]
    print(f"\nAbout to run {n_items} items ({len(attacks)} attacks + {len(benign)} benign) "
          f"through the {mode} pipeline.")
    print(f"Estimated: ~{est_calls} real API calls across {providers}, "
          f"likely a few minutes and well under $1.")
    if not skip_confirm:
        if input("Proceed? (y/n): ").strip().lower() != "y":
            print("Aborted.")
            return

    rows = []
    for kind, items in (("attack", attacks), ("benign", benign)):
        for item in items:
            r = run_item(item, mode)
            if r is None:
                continue
            print(f"  {kind:<7} {item['name']:<42} -> {r.final_decision}"
                  f"{' (verifier override)' if r.overridden_by_verifier else ''}")
            row = {
                "kind": kind, "name": item["name"], "target": item["target"],
                "final_decision": r.final_decision,
                "executor_decision": r.executor_decision, "executor_reason": r.executor_reason,
                "verifier_audit": r.verifier_audit or "", "verifier_reason": r.verifier_reason or "",
                "overridden_by_verifier": r.overridden_by_verifier,
                "fail_safe_triggered": r.fail_safe_triggered,
                "cost_usd": round(r.total_cost_usd, 5), "latency_ms": round(r.total_latency_ms, 1),
                "sanitized_summary": r.sanitized_summary[:300],
                # hybrid-only columns -- blank for two/three so the CSV schema
                # stays uniform across all modes (aggregate_repeats.py reads
                # columns by name, so extra/blank fields never break it)
                "agent_decision": getattr(r, "agent_decision", ""),
                "risk_decision": getattr(r, "risk_decision", ""),
                "risk_score": getattr(r, "risk_score", ""),
                "combined_from": getattr(r, "combined_from", ""),
            }
            rows.append(row)

    n = len(rows)
    a_allow = sum(1 for r in rows if r["kind"] == "attack" and r["final_decision"] == "ALLOW")
    a_confirm = sum(1 for r in rows if r["kind"] == "attack" and r["final_decision"] == "CONFIRM")
    a_total = sum(1 for r in rows if r["kind"] == "attack")
    b_block = sum(1 for r in rows if r["kind"] == "benign" and r["final_decision"] == "BLOCK")
    b_confirm = sum(1 for r in rows if r["kind"] == "benign" and r["final_decision"] == "CONFIRM")
    b_total = sum(1 for r in rows if r["kind"] == "benign")
    total_cost = sum(r["cost_usd"] for r in rows)
    total_latency = sum(r["latency_ms"] for r in rows)

    print(f"\n{'='*70}")
    print(f"  {mode.upper()} RESULTS -- channel={channel}")
    if a_total:
        extra = f"  (+{a_confirm} confirm)" if mode == "hybrid" else ""
        print(f"  Attack bypass rate: {a_allow}/{a_total} ({a_allow/a_total:.0%}){extra}")
    else:
        print("  No attacks in this channel.")
    if b_total:
        extra = f"  (+{b_confirm} confirm)" if mode == "hybrid" else ""
        print(f"  Benign false-positive rate: {b_block}/{b_total} ({b_block/b_total:.0%}){extra}")
    else:
        print("  No benign items in this channel.")
    if n:
        print(f"  Total cost: ${total_cost:.4f}   Total latency: {total_latency/1000:.1f}s"
              f"   Mean latency/item: {total_latency/n:.0f}ms")
    print(f"{'='*70}\n")

    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / f"two_agent_{channel}_{mode}.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {out}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        smoke_test()
        sys.exit(0)

    if len(sys.argv) < 2 or sys.argv[1] not in ATTACK_SETS:
        print(f"""
Usage:
  python -m two_agent.run_two_agent test                    # cheap smoke test (~6 calls)
  python -m two_agent.run_two_agent <channel> [mode] [--yes]

  channel = core / email / web / file / all
  mode    = two (sanitizer+executor) / three (default, +verifier) / hybrid (agents + risk_llm, 3-way)
  --yes   = skip the cost confirmation prompt
""")
        sys.exit(1)

    channel = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] in ("two", "three", "hybrid") else "three"
    skip_confirm = "--yes" in sys.argv
    full_run(channel, mode, skip_confirm)
