# tests/diagnostics/tune_weights.py
#
# Finds the classifier weight + band thresholds that MINIMIZE human
# confirmations while making ZERO errors, where an error is:
#
#   * a LIVE attack (payload survived parsing) scored below the allow line
#   * a BENIGN task scored at/above the block line
#
# Attacks whose payload was already stripped by the parser are NOT live: for
# those, ALLOW is the correct answer (nothing malicious reached the agent), so
# allowing them costs no human and is not a miss.
#
# The LLM confidence for each item is fetched ONCE and cached to
# .llm_cache.json, so re-running a sweep costs no API calls.
#
#   PYTHONPATH=. venv/bin/python -m tests.diagnostics.tune_weights

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from defenses.risk import (
    LLMJudgeClassifier, source_risk, target_risk, pattern_risk, recipient_risk,
)
from defenses.input_sanitizer import WriteContext
from tests.attacks.core import ATTACKS as CORE_A, BENIGN_TASKS as CORE_B
from tests.attacks.email import EMAIL_ATTACKS as EMAIL_A, EMAIL_BENIGN as EMAIL_B
from tests.attacks.web import WEB_ATTACKS as WEB_A, WEB_BENIGN as WEB_B
from tests.attacks.file import FILE_ATTACKS as FILE_A, FILE_BENIGN as FILE_B
from tests.transport import pipeline

CACHE = Path(__file__).resolve().parent.parent.parent / ".llm_cache.json"

# Attacks whose assigned extractor REMOVES the payload before scoring. The
# text that reaches the defense is genuinely benign, so ALLOW is correct.
# (Verified against the extractor previews -- see tests/attacks/*.py.)
PARSER_STRIPPED = {
    "web_hard_css_hidden_vs_hardened",      # bs4_visible_only drops display:none
    "email_medium_html_part_injection",     # plaintext_only never reads the html part
    "email_hard_html_comment_in_part",      # bs4_get_text drops comment nodes
    "file_hard_pdf_hardened_check",         # pdf_color_filtered drops white text
    "file_pdf_color_filter_gap",            # pdf_color_filtered drops white text
}

ATTACKS = CORE_A + EMAIL_A + WEB_A + FILE_A
BENIGN = CORE_B + EMAIL_B + WEB_B + FILE_B

BASE_W = {"source": 0.25, "target": 0.15, "pattern": 0.25, "recipient": 0.20}


def extract_text(item):
    if "raw" in item or "spec" in item:
        return pipeline.extract_direct(item, item.get("extract"))
    if "payload" in item:
        return item["payload"]
    return item["content"]


def build_rows():
    """One row per item: its four signals + the (cached) LLM confidence."""
    cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    judge = LLMJudgeClassifier()
    rows = []
    for kind, items in (("attack", ATTACKS), ("benign", BENIGN)):
        for item in items:
            text = extract_text(item)
            if not text.strip():
                continue
            name = item["name"]
            ctx = WriteContext(item["target"], text, item.get("source", "external"))
            if name not in cache:
                conf = judge.confidence(ctx)
                if conf is None:
                    print(f"  ! LLM judge failed on {name}; aborting")
                    sys.exit(1)
                cache[name] = conf
                print(f"  fetched {name}: {conf:.2f}")
            rows.append({
                "name": name,
                "kind": kind,
                "live": kind == "attack" and name not in PARSER_STRIPPED,
                "signals": {
                    "source": source_risk(ctx.source),
                    "target": target_risk(ctx.target_file),
                    "pattern": pattern_risk(ctx.content),
                    "recipient": recipient_risk(ctx.content),
                },
                "classifier": cache[name],
            })
    CACHE.write_text(json.dumps(cache, indent=2))
    if judge.calls:
        print(f"  ({judge.calls} new API calls; cached to {CACHE.name})\n")
    return rows


def score(row, w_cls):
    """Same maths as RiskScorer: weighted sum, renormalized by active weights."""
    total = sum(BASE_W.values()) + w_cls
    s = sum(BASE_W[k] * row["signals"][k] for k in BASE_W)
    s += w_cls * row["classifier"]
    return s / total


def best_bands(rows, w_cls):
    """Given a weight, pick the bands that minimize confirmations with zero
    errors. The widest safe allow-line is the lowest-scoring LIVE attack; the
    lowest safe block-line is just above the highest-scoring benign."""
    live = [score(r, w_cls) for r in rows if r["live"]]
    benign = [score(r, w_cls) for r in rows if r["kind"] == "benign"]
    low = min(live)                 # any lower and a live attack gets allowed
    high = max(benign) + 1e-9       # any lower and a benign gets blocked
    return low, high


def evaluate(rows, w_cls, low, high):
    out = {"confirm": 0, "errors": 0,
           "a_allow": 0, "a_confirm": 0, "a_block": 0,
           "b_allow": 0, "b_confirm": 0, "b_block": 0}
    for r in rows:
        s = score(r, w_cls)
        d = "block" if s >= high else ("allow" if s < low else "confirm")
        pre = "a_" if r["kind"] == "attack" else "b_"
        out[pre + d] += 1
        if d == "confirm":
            out["confirm"] += 1
        if r["live"] and d == "allow":
            out["errors"] += 1          # live attack waved through
        if r["kind"] == "benign" and d == "block":
            out["errors"] += 1          # benign hard-blocked
    return out


def main():
    rows = build_rows()
    n_live = sum(1 for r in rows if r["live"])
    print(f"{'='*78}")
    print(f"  WEIGHT TUNING   items={len(rows)}  live-attacks={n_live}  "
          f"parser-stripped={len(PARSER_STRIPPED)}  benign={len(BENIGN)}")
    print(f"{'='*78}\n")
    print(f"  {'w_cls':>6} {'low':>6} {'high':>6} | {'confirm':>7} {'errors':>6} | "
          f"attacks a/c/b        benign a/c/b")
    print(f"  {'-'*76}")

    best = None
    for w in [0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.50, 0.60, 0.75, 1.00]:
        low, high = best_bands(rows, w)
        if high <= low:
            # benign and live attacks separate cleanly -> one line decides all
            low = high = (max(s for s in [score(r, w) for r in rows if r["kind"] == "benign"])
                          + min(score(r, w) for r in rows if r["live"])) / 2
        e = evaluate(rows, w, low, high)
        print(f"  {w:>6.2f} {low:>6.3f} {high:>6.3f} | {e['confirm']:>7} {e['errors']:>6} | "
              f"{e['a_allow']:>3}/{e['a_confirm']:>3}/{e['a_block']:>3}          "
              f"{e['b_allow']:>3}/{e['b_confirm']:>3}/{e['b_block']:>3}")
        if e["errors"] == 0 and (best is None or e["confirm"] < best[1]["confirm"]):
            best = (w, e, low, high)

    if best:
        w, e, low, high = best
        print(f"\n  BEST (zero errors, fewest humans):")
        print(f"    classifier weight = {w}")
        print(f"    LOW_BAND  = {low:.3f}   HIGH_BAND = {high:.3f}")
        print(f"    humans needed = {e['confirm']}/{len(rows)}  "
              f"({e['confirm']/len(rows):.0%} of traffic)")
    print(f"\n{'='*78}\n")


if __name__ == "__main__":
    main()
