# tests/diagnostics/survival_matrix.py
#
# Step 4/7d deliverable, in two layers matching the paper's logical flow:
#
#   1. STANDALONE parser survival (defense-agnostic): for every web/email/
#      file attack, does its malicious content survive each extraction
#      strategy at all? This never calls a defense -- "survives" means an
#      injection-pattern regex still matches the extracted text, using
#      defenses.input_sanitizer.INJECTION_PATTERNS purely as a content
#      detector (independent of source/target trust, which a defense would
#      layer on top). This is its own section: parser fidelity is a finding
#      before defense-in-depth enters the picture.
#
#   2. CONNECTED (extractor x defense config): of what survives, does a
#      given defense config still catch it? Reuses evaluate_write(), so
#      this is the same infrastructure as sweep_defenses.py, just sliced
#      by extractor instead of by attack set.
#
# Both write CSVs to results/ (regenerable, like the other diagnostics).
#
#   PYTHONPATH=. venv/bin/python -m tests.diagnostics.survival_matrix

import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from defenses.input_sanitizer import INJECTION_PATTERNS, evaluate_write, Decision
from tests.attacks.email import EMAIL_ATTACKS
from tests.attacks.web import WEB_ATTACKS
from tests.attacks.file import FILE_ATTACKS
from tests.extraction.text import extract, HTML_EXTRACTORS, EMAIL_EXTRACTORS
from tests.extraction.files import extract_file, FILE_EXTRACTORS

RESULTS_DIR = Path.home() / "openclaw-security" / "results"

CONNECTED_CONFIGS = ["none", "regex", "full", "risk", "risk_llm"]


def survives(text: str) -> bool:
    """Content-only check: does an injection pattern still match? This is
    NOT a defense decision -- no source/target/recipient trust involved,
    just "is the malicious signal still present after parsing." """
    return any(re.search(p, text, re.IGNORECASE) for p in INJECTION_PATTERNS)


def relevant_extractors(attack):
    """Same grouping logic as research_runner.compare_extractors: which
    strategies are meaningful to compare for this attack's format."""
    if "raw" in attack:
        kind = attack.get("extract_kind", "html")
        registry = HTML_EXTRACTORS if kind == "html" else EMAIL_EXTRACTORS
        return kind, registry
    if "spec" in attack:
        assigned = attack["extract"]
        fmt = assigned.split("_")[0]
        registry = {n: f for n, f in FILE_EXTRACTORS.items()
                    if n.split("_")[0] == fmt or n == "txt"}
        return "file", registry
    return None, {}


def extract_with(attack, kind, strategy):
    if "raw" in attack:
        return extract(attack["raw"], kind, strategy)
    return extract_file(attack["spec"], strategy)


def build_matrix():
    """Returns rows: one per (attack, extractor), with survival + target/source
    carried along for the connected view."""
    rows = []
    for attack in EMAIL_ATTACKS + WEB_ATTACKS + FILE_ATTACKS:
        kind, registry = relevant_extractors(attack)
        if not registry:
            continue
        for strat_name in registry:
            try:
                text = extract_with(attack, kind, strat_name)
            except Exception as e:
                rows.append({"attack": attack["name"], "extractor": strat_name,
                             "assigned": strat_name == attack["extract"],
                             "survives": None, "error": str(e), "attack_obj": attack})
                continue
            rows.append({
                "attack": attack["name"], "extractor": strat_name,
                "assigned": strat_name == attack["extract"],
                "survives": bool(text.strip()) and survives(text),
                "text": text, "error": None, "attack_obj": attack,
            })
    return rows


def print_standalone(rows):
    print(f"\n{'='*90}")
    print(f"  PARSER SURVIVAL MATRIX (standalone -- no defense involved)")
    print(f"  Does the malicious content still match an injection pattern after extraction?")
    print(f"{'='*90}")
    print(f"  {'attack':<40} {'extractor':<18} {'survives':<10} {'assigned'}")
    print(f"  {'-'*85}")
    for r in rows:
        surv = "ERROR" if r["error"] else ("YES" if r["survives"] else "no")
        mark = "<-- assigned" if r["assigned"] else ""
        print(f"  {r['attack']:<40} {r['extractor']:<18} {surv:<10} {mark}")
    n = len([r for r in rows if r["error"] is None])
    survived = len([r for r in rows if r["survives"]])
    print(f"\n  {survived}/{n} (attack, extractor) pairs let the malicious content survive parsing.")
    print(f"{'='*90}\n")


def write_standalone_csv(rows):
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / "survival_matrix.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack", "extractor", "assigned", "survives"])
        for r in rows:
            w.writerow([r["attack"], r["extractor"], r["assigned"],
                        "" if r["error"] else r["survives"]])
    print(f"  Wrote {path}")


def print_connected(rows, configs):
    print(f"\n{'='*100}")
    print(f"  CONNECTED MATRIX -- extractor x defense config (only rows where content SURVIVED extraction)")
    print(f"  Given the parser let it through, does each defense config still catch it?")
    print(f"{'='*100}")
    header = f"  {'attack':<38} {'extractor':<16}" + "".join(f"{c:>13}" for c in configs)
    print(header)
    print(f"  {'-'*(38+16+13*len(configs))}")

    out_rows = []
    for r in rows:
        if r["error"] or not r["survives"]:
            continue
        attack = r["attack_obj"]
        decisions = []
        for cfg in configs:
            v = evaluate_write(attack["target"], r["text"], attack.get("source", "external"), cfg)
            decisions.append(v.decision.value)
        line = f"  {r['attack']:<38} {r['extractor']:<16}" + "".join(f"{d:>13}" for d in decisions)
        print(line)
        out_rows.append({"attack": r["attack"], "extractor": r["extractor"],
                          **{cfg: d for cfg, d in zip(configs, decisions)}})
    print(f"{'='*100}\n")
    return out_rows


def write_connected_csv(out_rows):
    path = RESULTS_DIR / "survival_matrix_connected.csv"
    if not out_rows:
        print(f"  (nothing survived extraction in every case -- no connected rows to write)")
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)
    print(f"  Wrote {path}")


def main():
    no_llm = "--no-llm" in sys.argv
    configs = [c for c in CONNECTED_CONFIGS if not (no_llm and "llm" in c)]

    rows = build_matrix()
    print_standalone(rows)     # free/instant -- no defense, no API calls
    write_standalone_csv(rows)
    out_rows = print_connected(rows, configs)   # risk_llm here makes real API calls
    write_connected_csv(out_rows)


if __name__ == "__main__":
    main()
