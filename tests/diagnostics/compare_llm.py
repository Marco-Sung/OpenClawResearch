# tests/diagnostics/compare_llm.py
#
# Measures the OFFLINE risk scorer against the LLM-augmented one (risk_llm) on
# the same inputs, and reports:
#   * how the allow / confirm / block split changes (does the confirm pile shrink?)
#   * false positives (benign hard-blocked) and attack catches
#   * real latency and token cost of the LLM judge
#
#   PYTHONPATH=. venv/bin/python -m tests.diagnostics.compare_llm
#
# Makes ~1 API call per item for the risk_llm pass (needs ANTHROPIC_API_KEY in .env).

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from defenses.risk import (
    RiskScorer, LLMJudgeClassifier, LLM_LOW_BAND, LLM_HIGH_BAND,
)
from defenses.input_sanitizer import WriteContext, Decision
from tests.attacks.core import ATTACKS as CORE_A, BENIGN_TASKS as CORE_B
from tests.attacks.email import EMAIL_ATTACKS as EMAIL_A, EMAIL_BENIGN as EMAIL_B
from tests.attacks.web import WEB_ATTACKS as WEB_A, WEB_BENIGN as WEB_B
from tests.attacks.file import FILE_ATTACKS as FILE_A, FILE_BENIGN as FILE_B
from tests.transport import pipeline

# Claude Haiku 4.5 LIST PRICE (USD per million tokens). VERIFY current pricing
# before quoting in the paper -- see the professor's step 10.
PRICE_IN_PER_MTOK = 1.0
PRICE_OUT_PER_MTOK = 5.0

ATTACKS = CORE_A + EMAIL_A + WEB_A + FILE_A
BENIGN = CORE_B + EMAIL_B + WEB_B + FILE_B


def extract_text(item):
    if "raw" in item or "spec" in item:
        return pipeline.extract_direct(item, item.get("extract"))
    if "payload" in item:
        return item["payload"]
    return item["content"]


def tally(items, scorer):
    counts = {Decision.ALLOW: 0, Decision.CONFIRM: 0, Decision.BLOCK: 0}
    elapsed_ms = 0.0
    for item in items:
        text = extract_text(item)
        if not text.strip():
            continue
        ctx = WriteContext(item["target"], text, item.get("source", "external"))
        t = time.time()
        b = scorer.score(ctx)
        elapsed_ms += (time.time() - t) * 1000
        counts[b.decision] += 1
    return counts, elapsed_ms


def row(name, c, n):
    return (f"  {name:<9} allow={c[Decision.ALLOW]:>2}  confirm={c[Decision.CONFIRM]:>2}  "
            f"block={c[Decision.BLOCK]:>2}   (of {n})")


def main():
    judge = LLMJudgeClassifier()
    risk = RiskScorer()                       # offline, default bands
    risk_llm = RiskScorer(classifier=judge,   # + AI judge, tuned bands
                          low=LLM_LOW_BAND, high=LLM_HIGH_BAND)

    print(f"\n{'='*70}\n  risk  vs  risk_llm   attacks={len(ATTACKS)}  benign={len(BENIGN)}\n{'='*70}")

    print("\n  ATTACKS  (want: fewer confirm, more block; zero allow)")
    a_off, _ = tally(ATTACKS, risk)
    a_llm, _ = tally(ATTACKS, risk_llm)
    print(row("risk", a_off, len(ATTACKS)))
    print(row("risk_llm", a_llm, len(ATTACKS)))

    print("\n  BENIGN  (want: fewer confirm, more allow; zero block)")
    b_off, _ = tally(BENIGN, risk)
    b_llm, _ = tally(BENIGN, risk_llm)
    print(row("risk", b_off, len(BENIGN)))
    print(row("risk_llm", b_llm, len(BENIGN)))

    confirm_off = a_off[Decision.CONFIRM] + b_off[Decision.CONFIRM]
    confirm_llm = a_llm[Decision.CONFIRM] + b_llm[Decision.CONFIRM]

    # Cost + latency from the judge's own counters.
    cost = (judge.input_tokens / 1e6 * PRICE_IN_PER_MTOK
            + judge.output_tokens / 1e6 * PRICE_OUT_PER_MTOK)

    print(f"\n  {'-'*66}")
    print(f"  Confirm pile (needs a human):  risk={confirm_off}  ->  risk_llm={confirm_llm}")
    print(f"  LLM judge: {judge.calls} calls  "
          f"({judge.input_tokens} in + {judge.output_tokens} out tokens)")
    if judge.calls:
        print(f"  Cost: ${cost:.4f} total  (~${cost/judge.calls*1000:.3f} per 1000 calls)  "
              f"[Haiku list price, VERIFY]")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
