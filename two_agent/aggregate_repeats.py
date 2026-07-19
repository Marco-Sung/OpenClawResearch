# two_agent/aggregate_repeats.py
#
# Compiles every per-run CSV in two_agent/results/repeats/ into one table:
# exact counts (not percentages) per channel, summed across all runs, plus
# a per-run breakdown so you can see run-to-run spread directly.
#
#   python -m two_agent.aggregate_repeats

import csv
import glob
import re
from collections import defaultdict
from pathlib import Path

REPEATS_DIR = Path(__file__).resolve().parent / "results" / "repeats"
OUT_CSV = REPEATS_DIR.parent / "two_agent_compiled.csv"


def parse_filename(path):
    # two_agent_<channel>_<mode>_run<N>.csv
    m = re.match(r"two_agent_(\w+)_(two|three)_run(\d+)\.csv$", Path(path).name)
    return (m.group(1), m.group(2), int(m.group(3))) if m else (None, None, None)


def main():
    files = sorted(glob.glob(str(REPEATS_DIR / "*_run*.csv")))
    if not files:
        print(f"No run files found in {REPEATS_DIR}")
        return

    # per_run[(channel, mode, run)] = {attack_allow, attack_block, attack_n, benign_allow, benign_block, benign_n}
    per_run = {}
    overrides = defaultdict(int)   # (channel, mode) -> count of verifier overrides
    fail_safe = defaultdict(int)

    for f in files:
        channel, mode, run = parse_filename(f)
        if channel is None:
            continue
        counts = {"attack_allow": 0, "attack_block": 0, "attack_n": 0,
                  "benign_allow": 0, "benign_block": 0, "benign_n": 0}
        with open(f) as fh:
            for row in csv.DictReader(fh):
                kind = row["kind"]
                decision = row["final_decision"]
                counts[f"{kind}_n"] += 1
                if decision == "ALLOW":
                    counts[f"{kind}_allow"] += 1
                else:
                    counts[f"{kind}_block"] += 1
                if row.get("overridden_by_verifier") == "True":
                    overrides[(channel, mode)] += 1
                if row.get("fail_safe_triggered") == "True":
                    fail_safe[(channel, mode)] += 1
        per_run[(channel, mode, run)] = counts

    channels_modes = sorted(set((c, m) for c, m, _ in per_run))

    print(f"\n{'='*100}")
    print("  PER-RUN EXACT COUNTS")
    print(f"{'='*100}")
    print(f"  {'channel':<8}{'mode':<7}{'run':>4}   {'atk allow':>10}{'atk block':>11}{'atk n':>7}"
          f"   {'ben allow':>10}{'ben block':>11}{'ben n':>7}")
    for channel, mode in channels_modes:
        runs = sorted(r for c, m, r in per_run if c == channel and m == mode)
        for run in runs:
            c = per_run[(channel, mode, run)]
            print(f"  {channel:<8}{mode:<7}{run:>4}   {c['attack_allow']:>10}{c['attack_block']:>11}"
                  f"{c['attack_n']:>7}   {c['benign_allow']:>10}{c['benign_block']:>11}{c['benign_n']:>7}")
        print()

    print(f"{'='*100}")
    print("  TOTALS ACROSS ALL RUNS (sum of exact counts, not averaged/rounded)")
    print(f"{'='*100}")
    print(f"  {'channel':<8}{'mode':<7}{'runs':>5}   {'atk allow':>10}{'atk block':>11}{'atk n':>7}"
          f"   {'ben allow':>10}{'ben block':>11}{'ben n':>7}   {'overrides':>10}{'fail-safe':>10}")
    compiled_rows = []
    for channel, mode in channels_modes:
        runs = sorted(r for c, m, r in per_run if c == channel and m == mode)
        totals = {"attack_allow": 0, "attack_block": 0, "attack_n": 0,
                  "benign_allow": 0, "benign_block": 0, "benign_n": 0}
        for run in runs:
            c = per_run[(channel, mode, run)]
            for k in totals:
                totals[k] += c[k]
        ov = overrides[(channel, mode)]
        fs = fail_safe[(channel, mode)]
        print(f"  {channel:<8}{mode:<7}{len(runs):>5}   {totals['attack_allow']:>10}{totals['attack_block']:>11}"
              f"{totals['attack_n']:>7}   {totals['benign_allow']:>10}{totals['benign_block']:>11}"
              f"{totals['benign_n']:>7}   {ov:>10}{fs:>10}")
        compiled_rows.append({"channel": channel, "mode": mode, "runs": len(runs), **totals,
                               "verifier_overrides": ov, "fail_safe_rows": fs})
    print(f"{'='*100}\n")

    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(compiled_rows[0].keys()))
        w.writeheader()
        w.writerows(compiled_rows)
    print(f"Wrote {OUT_CSV}\n")


if __name__ == "__main__":
    main()
