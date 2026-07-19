# tests/diagnostics/make_stacked_table.py
#
# Booktabs LaTeX tables of allow/confirm/block outcomes, grouped the same
# way as make_stacked_chart.py ("individual" / "risk" / "all") so the paper
# can present the baseline mechanisms and the risk-scoring proposal as
# separate tables, while "all" gives one combined table if needed.
#
#   venv/bin/python -m tests.diagnostics.make_stacked_table individual
#   venv/bin/python -m tests.diagnostics.make_stacked_table risk
#   venv/bin/python -m tests.diagnostics.make_stacked_table all

import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

from tests.diagnostics.defense_groups import GROUPS, DISPLAY_NAME
from tests.diagnostics.defense_rows import build_rows

RESULTS_DIR = Path.home() / "openclaw-security" / "results"


def name_for_tex(config):
    return DISPLAY_NAME.get(config, config).replace("\n", " ")


def pct(count, n):
    return f"{count / n * 100:.0f}\\%"


def section(rows, key_prefix, caption, label):
    lines = [
        r"\begin{table}[htbp]", r"\centering",
        rf"\caption{{{caption}}}", rf"\label{{{label}}}",
        r"\begin{tabular}{lrrrl}", r"\toprule",
        r"Defense config & Allow & Confirm & Block & Basis \\", r"\midrule",
    ]
    for r in rows:
        n = r[f"{key_prefix}_n"]
        basis = f"mean of {r['runs']} runs" if r["runs"] > 1 else "single run (deterministic)"
        lines.append(
            f"{name_for_tex(r['config'])} & {pct(r[f'{key_prefix}_allow'], n)} & "
            f"{pct(r[f'{key_prefix}_confirm'], n)} & {pct(r[f'{key_prefix}_block'], n)} & "
            f"{basis} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    return lines


def main():
    group = sys.argv[1] if len(sys.argv) > 1 else "all"
    if group not in GROUPS:
        print(f"Unknown group '{group}'. Choose from: {list(GROUPS.keys())}")
        sys.exit(1)

    rows = build_rows(GROUPS[group])
    group_desc = {"individual": "individual defense mechanisms",
                  "risk": "risk-scoring configs", "all": "all defense configs"}[group]

    out = ["% Requires \\usepackage{booktabs} in the preamble.",
           "% Auto-generated -- do not hand-edit; re-run",
           "% tests/diagnostics/make_stacked_table.py instead.",
           "% risk_llm rows are the mean of 10 repeated runs (see",
           "% risk_llm_repeats_data.py); all other configs are deterministic",
           "% (no randomness), so a single run fully characterizes them.", ""]
    out += section(rows, "attack",
                    f"Attack outcomes for {group_desc} (27 attacks, all channels, direct mode).",
                    f"tab:stacked-{group}-attacks")
    out += section(rows, "benign",
                    f"Benign task outcomes for {group_desc} (24 benign tasks).",
                    f"tab:stacked-{group}-benign")

    out_path = RESULTS_DIR / f"stacked_{group}_table.tex"
    out_path.write_text("\n".join(out))
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
