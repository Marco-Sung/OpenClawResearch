# two_agent/make_compiled_table.py
#
# Renders two_agent_compiled.csv as a booktabs LaTeX table -- exact counts,
# not percentages, matching how the main defense system's tables are built.
#
#   python -m two_agent.make_compiled_table

import csv
from pathlib import Path

COMPILED_CSV = Path(__file__).resolve().parent / "results" / "two_agent_compiled.csv"
OUT_TEX = Path(__file__).resolve().parent / "results" / "two_agent_compiled_table.tex"

MODE_LABEL = {"two": "2-agent", "three": "3-agent", "hybrid": "Hybrid (+risk\\_llm)"}


def main():
    with open(COMPILED_CSV) as f:
        rows = list(csv.DictReader(f))

    out = [
        r"% Requires \usepackage{booktabs}. Auto-generated -- do not hand-edit;",
        r"% re-run two_agent/aggregate_repeats.py then make_compiled_table.py.",
        "",
        r"\begin{table}[htbp]", r"\centering",
        r"\caption{two\_agent exact outcome counts, summed across all repeated runs.}",
        r"\label{tab:two-agent-compiled}",
        r"\begin{tabular}{llrrrrrrr}",
        r"\toprule",
        r"Channel & Mode & Runs & Atk Allow & Atk Block & Atk $n$ & Ben Allow & Ben Block & Ben $n$ \\",
        r"\midrule",
    ]
    for r in rows:
        out.append(
            f"{r['channel']} & {MODE_LABEL.get(r['mode'], r['mode'])} & {r['runs']} & "
            f"{r['attack_allow']} & {r['attack_block']} & {r['attack_n']} & "
            f"{r['benign_allow']} & {r['benign_block']} & {r['benign_n']} \\\\"
        )
    out += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]

    OUT_TEX.write_text("\n".join(out))
    print(f"Wrote {OUT_TEX}")


if __name__ == "__main__":
    main()
