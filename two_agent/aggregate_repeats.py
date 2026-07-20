# two_agent/aggregate_repeats.py
#
# Compiles every per-run CSV in two_agent/results/repeats/ into one table:
# exact counts (not percentages) per channel/mode, summed across all runs,
# plus a per-run breakdown so you can see run-to-run spread directly.
#
# Handles all three modes uniformly -- two/three are binary (ALLOW/BLOCK,
# confirm always 0), hybrid is three-way (ALLOW/CONFIRM/BLOCK, via risk_llm).
#
#   python -m two_agent.aggregate_repeats

import csv
import glob
import re
from collections import defaultdict
from pathlib import Path

REPEATS_DIR = Path(__file__).resolve().parent / "results" / "repeats"
OUT_CSV = REPEATS_DIR.parent / "two_agent_compiled.csv"

COUNT_FIELDS = ["attack_allow", "attack_confirm", "attack_block", "attack_n",
                "benign_allow", "benign_confirm", "benign_block", "benign_n"]


def parse_filename(path):
    # two_agent_<channel>_<mode>_run<N>.csv
    m = re.match(r"two_agent_(\w+)_(two|three|hybrid)_run(\d+)\.csv$", Path(path).name)
    return (m.group(1), m.group(2), int(m.group(3))) if m else (None, None, None)


def blank_counts():
    return {k: 0 for k in COUNT_FIELDS}


def main():
    files = sorted(glob.glob(str(REPEATS_DIR / "*_run*.csv")))
    if not files:
        print(f"No run files found in {REPEATS_DIR}")
        return

    per_run = {}
    overrides = defaultdict(int)
    fail_safe = defaultdict(int)
    combined_from_risk = defaultdict(int)   # hybrid only: how often risk_llm (not the agents) decided

    for f in files:
        channel, mode, run = parse_filename(f)
        if channel is None:
            continue
        counts = blank_counts()
        with open(f) as fh:
            for row in csv.DictReader(fh):
                kind = row["kind"]
                decision = row["final_decision"]
                counts[f"{kind}_n"] += 1
                if decision == "ALLOW":
                    counts[f"{kind}_allow"] += 1
                elif decision == "CONFIRM":
                    counts[f"{kind}_confirm"] += 1
                else:
                    counts[f"{kind}_block"] += 1
                if row.get("overridden_by_verifier") == "True":
                    overrides[(channel, mode)] += 1
                if row.get("fail_safe_triggered") == "True":
                    fail_safe[(channel, mode)] += 1
                if row.get("combined_from") == "risk_llm":
                    combined_from_risk[(channel, mode)] += 1
        per_run[(channel, mode, run)] = counts

    channels_modes = sorted(set((c, m) for c, m, _ in per_run))

    def header():
        return (f"  {'channel':<8}{'mode':<8}{'run/#':>6}   {'atk A':>6}{'atk C':>6}{'atk B':>6}{'atk n':>6}"
                f"   {'ben A':>6}{'ben C':>6}{'ben B':>6}{'ben n':>6}")

    print(f"\n{'='*100}")
    print("  PER-RUN EXACT COUNTS  (A=allow, C=confirm, B=block)")
    print(f"{'='*100}")
    print(header())
    for channel, mode in channels_modes:
        runs = sorted(r for c, m, r in per_run if c == channel and m == mode)
        for run in runs:
            c = per_run[(channel, mode, run)]
            print(f"  {channel:<8}{mode:<8}{run:>6}   {c['attack_allow']:>6}{c['attack_confirm']:>6}"
                  f"{c['attack_block']:>6}{c['attack_n']:>6}   {c['benign_allow']:>6}{c['benign_confirm']:>6}"
                  f"{c['benign_block']:>6}{c['benign_n']:>6}")
        print()

    print(f"{'='*100}")
    print("  TOTALS ACROSS ALL RUNS (sum of exact counts, not averaged/rounded)")
    print(f"{'='*100}")
    print(header())
    compiled_rows = []
    for channel, mode in channels_modes:
        runs = sorted(r for c, m, r in per_run if c == channel and m == mode)
        totals = blank_counts()
        for run in runs:
            c = per_run[(channel, mode, run)]
            for k in totals:
                totals[k] += c[k]
        ov, fs, cfr = overrides[(channel, mode)], fail_safe[(channel, mode)], combined_from_risk[(channel, mode)]
        print(f"  {channel:<8}{mode:<8}{len(runs):>6}   {totals['attack_allow']:>6}{totals['attack_confirm']:>6}"
              f"{totals['attack_block']:>6}{totals['attack_n']:>6}   {totals['benign_allow']:>6}"
              f"{totals['benign_confirm']:>6}{totals['benign_block']:>6}{totals['benign_n']:>6}"
              f"   overrides={ov}  fail-safe={fs}  risk_llm-decided={cfr}")
        compiled_rows.append({"channel": channel, "mode": mode, "runs": len(runs), **totals,
                               "verifier_overrides": ov, "fail_safe_rows": fs,
                               "combined_from_risk_llm": cfr})
    print(f"{'='*100}\n")

    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(compiled_rows[0].keys()))
        w.writeheader()
        w.writerows(compiled_rows)
    print(f"Wrote {OUT_CSV}\n")


if __name__ == "__main__":
    main()
