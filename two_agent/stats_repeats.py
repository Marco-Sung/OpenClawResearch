# two_agent/stats_repeats.py
#
# Computes mean +/- standard deviation ACROSS the 10 repeated runs per
# channel/mode (not summed totals -- aggregate_repeats.py already does
# that). Each run's exact count (e.g. "how many of the 5 file attacks were
# allowed in THIS run") becomes one data point; mean/stdev are taken across
# those 10 data points, which is what actually answers "how much does this
# vary run to run."
#
#   python -m two_agent.stats_repeats [mode1 mode2 ...]
#   python -m two_agent.stats_repeats            # defaults to three + hybrid

import csv
import glob
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

REPEATS_DIR = Path(__file__).resolve().parent / "results" / "repeats"
FIELDS = ["attack_allow", "attack_confirm", "attack_block",
          "benign_allow", "benign_confirm", "benign_block"]


def parse_filename(path):
    m = re.match(r"two_agent_(\w+)_(two|three|hybrid)_run(\d+)\.csv$", Path(path).name)
    return (m.group(1), m.group(2), int(m.group(3))) if m else (None, None, None)


def per_run_counts(path):
    counts = {k: 0 for k in FIELDS}
    n = {"attack": 0, "benign": 0}
    with open(path) as f:
        for row in csv.DictReader(f):
            kind, decision = row["kind"], row["final_decision"]
            n[kind] += 1
            if decision == "ALLOW":
                counts[f"{kind}_allow"] += 1
            elif decision == "CONFIRM":
                counts[f"{kind}_confirm"] += 1
            else:
                counts[f"{kind}_block"] += 1
    return counts, n


def main():
    target_modes = sys.argv[1:] or ["three", "hybrid"]

    # data[(channel, mode)] = list of per-run count dicts
    data = defaultdict(list)
    n_items = {}
    for f in sorted(glob.glob(str(REPEATS_DIR / "*_run*.csv"))):
        channel, mode, run = parse_filename(f)
        if channel is None or mode not in target_modes:
            continue
        counts, n = per_run_counts(f)
        data[(channel, mode)].append(counts)
        n_items[(channel, mode)] = n

    if not data:
        print(f"No run data found for modes {target_modes} in {REPEATS_DIR}")
        return

    print(f"\n{'='*104}")
    print(f"  MEAN +/- STD DEV ACROSS RUNS  (modes: {', '.join(target_modes)})")
    print(f"  Each value = mean count per run (out of n items), +/- sample std dev (N-1) across the runs")
    print(f"{'='*104}")
    print(f"  {'channel':<8}{'mode':<8}{'runs':>5}  "
          f"{'atk allow':>16}{'atk confirm':>16}{'atk block':>16}   {'(n)':>4}")
    print(f"  {'':8}{'':8}{'':5}  {'-'*48}")

    rows_out = []
    for (channel, mode), runs in sorted(data.items()):
        n = n_items[(channel, mode)]

        def fmt(field):
            vals = [r[field] for r in runs]
            mean = statistics.mean(vals)
            # Sample std dev (N-1, Bessel's correction), not population --
            # these 10 runs are a SAMPLE of the LLM's possible behavior, not
            # the entire population of it, so N-1 is the standard, defensible
            # choice for reporting spread of a repeated experiment.
            std = statistics.stdev(vals) if len(vals) > 1 else 0.0
            return f"{mean:5.2f} +/- {std:4.2f}", mean, std

        a_allow_s, a_allow_m, a_allow_sd = fmt("attack_allow")
        a_conf_s, a_conf_m, a_conf_sd = fmt("attack_confirm")
        a_block_s, a_block_m, a_block_sd = fmt("attack_block")
        print(f"  {channel:<8}{mode:<8}{len(runs):>5}  "
              f"{a_allow_s:>16}{a_conf_s:>16}{a_block_s:>16}   {n['attack']:>4}")

        b_allow_s, b_allow_m, b_allow_sd = fmt("benign_allow")
        b_conf_s, b_conf_m, b_conf_sd = fmt("benign_confirm")
        b_block_s, b_block_m, b_block_sd = fmt("benign_block")
        print(f"  {'':8}{'(benign)':8}{'':5}  "
              f"{b_allow_s:>16}{b_conf_s:>16}{b_block_s:>16}   {n['benign']:>4}")
        print()

        rows_out.append({
            "channel": channel, "mode": mode, "runs": len(runs),
            "attack_n": n["attack"], "benign_n": n["benign"],
            "attack_allow_mean": round(a_allow_m, 3), "attack_allow_std": round(a_allow_sd, 3),
            "attack_confirm_mean": round(a_conf_m, 3), "attack_confirm_std": round(a_conf_sd, 3),
            "attack_block_mean": round(a_block_m, 3), "attack_block_std": round(a_block_sd, 3),
            "benign_allow_mean": round(b_allow_m, 3), "benign_allow_std": round(b_allow_sd, 3),
            "benign_confirm_mean": round(b_conf_m, 3), "benign_confirm_std": round(b_conf_sd, 3),
            "benign_block_mean": round(b_block_m, 3), "benign_block_std": round(b_block_sd, 3),
        })
    print(f"{'='*104}\n")

    out_csv = REPEATS_DIR.parent / "two_agent_run_stats.csv"
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        w.writeheader()
        w.writerows(rows_out)
    print(f"Wrote {out_csv}\n")


if __name__ == "__main__":
    main()
