# tests/diagnostics/defense_rows.py
#
# Builds one allow/confirm/block row per config, for the grouped stacked
# charts/tables. Deterministic configs are evaluated live (a single pass is
# exact, since there's no randomness -- see sweep_defenses.py for the same
# reasoning). risk_llm instead uses the empirical mean of 10 real runs from
# risk_llm_repeats_data.py, rather than one fresh API call, since a single
# call would only add noise (and cost) on top of information the repeated
# runs already captured.

import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from defenses.input_sanitizer import evaluate_write, Decision
from tests.attacks.core import ATTACKS as CORE_A, BENIGN_TASKS as CORE_B
from tests.attacks.email import EMAIL_ATTACKS as EMAIL_A, EMAIL_BENIGN as EMAIL_B
from tests.attacks.web import WEB_ATTACKS as WEB_A, WEB_BENIGN as WEB_B
from tests.attacks.file import FILE_ATTACKS as FILE_A, FILE_BENIGN as FILE_B
from tests.transport import pipeline
from tests.diagnostics.risk_llm_repeats_data import mean_counts

ATTACKS = CORE_A + EMAIL_A + WEB_A + FILE_A
BENIGN = CORE_B + EMAIL_B + WEB_B + FILE_B


def extract_text(item):
    if "raw" in item or "spec" in item:
        return pipeline.extract_direct(item, item.get("extract"))
    return item.get("payload", item.get("content", ""))


def _live_counts(config, items):
    counts = {Decision.ALLOW: 0, Decision.CONFIRM: 0, Decision.BLOCK: 0}
    for item in items:
        text = extract_text(item)
        if not text.strip():
            continue
        v = evaluate_write(item["target"], text, item.get("source", "external"), config)
        counts[v.decision] += 1
    return counts[Decision.ALLOW], counts[Decision.CONFIRM], counts[Decision.BLOCK]


def build_rows(configs):
    """One dict per config: attack_{allow,confirm,block,n} and
    benign_{allow,confirm,block,n}, plus 'runs' (1 = deterministic single
    pass, 10 = empirical mean of 10 runs)."""
    rows = []
    for config in configs:
        if config == "risk_llm":
            aa, ac, ab = mean_counts("attack")
            ba, bc, bb = mean_counts("benign")
            runs = 10
        else:
            aa, ac, ab = _live_counts(config, ATTACKS)
            ba, bc, bb = _live_counts(config, BENIGN)
            runs = 1
        rows.append({
            "config": config,
            "attack_allow": aa, "attack_confirm": ac, "attack_block": ab,
            "attack_n": len(ATTACKS),
            "benign_allow": ba, "benign_confirm": bc, "benign_block": bb,
            "benign_n": len(BENIGN),
            "runs": runs,
        })
    return rows
