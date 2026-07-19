# tests/diagnostics/make_stacked_chart.py
#
# 100%-stacked allow/confirm/block bar charts, split by group so the paper
# can show "individual defenses" and "risk scoring" as separate figures
# (cleaner narrative), while the poster gets everything in one ("all").
#
# Status colors (allow=good, confirm=warning, block=critical) are used
# deliberately: allow/confirm/block is an ordered severity scale, which is
# exactly what the status palette is for -- not arbitrary category identity.
# Every segment carries a direct value label, which is the documented
# mitigation for the warning color's low background contrast.
#
#   venv/bin/python -m tests.diagnostics.make_stacked_chart individual
#   venv/bin/python -m tests.diagnostics.make_stacked_chart risk
#   venv/bin/python -m tests.diagnostics.make_stacked_chart all

import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patheffects as pe

from tests.diagnostics.defense_groups import GROUPS, DISPLAY_NAME
from tests.diagnostics.defense_rows import build_rows

RESULTS_DIR = Path.home() / "openclaw-security" / "results"

GOOD = "#0ca30c"       # allow
WARNING = "#fab219"    # confirm
CRITICAL = "#d03b3b"   # block
INK = "#0b0b0b"
MUTED = "#52514e"


def pct_triplet(allow, confirm, block, n):
    return (allow / n * 100, confirm / n * 100, block / n * 100)


def draw_panel(ax, rows, key_prefix, title, label_min_pct, fontsizes):
    labels = [DISPLAY_NAME.get(r["config"], r["config"]) for r in rows]
    triplets = [pct_triplet(r[f"{key_prefix}_allow"], r[f"{key_prefix}_confirm"],
                             r[f"{key_prefix}_block"], r[f"{key_prefix}_n"]) for r in rows]

    x = range(len(rows))
    bottoms = [0.0] * len(rows)
    for seg_idx, (color, name) in enumerate([(GOOD, "Allowed"), (WARNING, "Confirm"), (CRITICAL, "Blocked")]):
        heights = [t[seg_idx] for t in triplets]
        bars = ax.bar(list(x), heights, bottom=bottoms, width=0.62, color=color,
                       label=name, zorder=3, edgecolor="white", linewidth=1.2)
        for i, (b, h) in enumerate(zip(bars, heights)):
            if h >= label_min_pct:
                y = bottoms[i] + h / 2
                txt = ax.text(b.get_x() + b.get_width() / 2, y, f"{h:.0f}%",
                               ha="center", va="center", fontsize=fontsizes["seg"],
                               fontweight="bold", color=INK, zorder=4)
                txt.set_path_effects([pe.withStroke(linewidth=2.5, foreground="white")])
        bottoms = [bo + h for bo, h in zip(bottoms, heights)]

    ax.set_ylim(0, 100)
    ax.set_xticks(list(x))
    xt_labels = []
    for r in rows:
        lbl = DISPLAY_NAME.get(r["config"], r["config"])   # already 1-2 lines, kept narrow on purpose
        if r["runs"] > 1:
            lbl += f"\n(mean of {r['runs']} runs)"
        xt_labels.append(lbl)
    ax.set_xticklabels(xt_labels, fontsize=fontsizes["tick"], color=INK, linespacing=1.35)
    ax.tick_params(axis="y", labelsize=fontsizes["tick"], colors=MUTED)
    ax.tick_params(axis="x", length=0)
    ax.set_ylabel("Share of items (%)", fontsize=fontsizes["axis"], color=INK)
    ax.set_title(title, fontsize=fontsizes["panel_title"], fontweight="bold", color=INK, pad=14)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color("#d8d7d0")
    ax.yaxis.grid(True, color="#eeeeea", linewidth=1, zorder=0)
    ax.set_axisbelow(True)


def render(group):
    if group not in GROUPS:
        print(f"Unknown group '{group}'. Choose from: {list(GROUPS.keys())}")
        sys.exit(1)

    rows = build_rows(GROUPS[group])
    poster = (group == "all")

    n = len(rows)
    fontsizes = (dict(seg=15, tick=14, axis=17, panel_title=19, sup_title=23, legend=16)
                 if poster else
                 dict(seg=10, tick=10, axis=12, panel_title=13, sup_title=15, legend=11))
    # Scale width to the number of bars so tick labels never collide,
    # regardless of how many configs a group ends up with (step 4/5 will
    # add more). Each bar needs enough width for its widest label LINE
    # (labels wrap to 2 lines -- see defense_groups.DISPLAY_NAME -- so this
    # is per-line width, not full-label width).
    figsize = (max(11, 3.1 * n), 9.5) if poster else (max(6, 2.4 * n), 5.1)
    label_min_pct = 4 if poster else 6

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=figsize, dpi=300)
    fig.patch.set_facecolor("white")
    for ax in (ax1, ax2):
        ax.set_facecolor("white")

    draw_panel(ax1, rows, "attack", "Attacks", label_min_pct, fontsizes)
    draw_panel(ax2, rows, "benign", "Benign tasks", label_min_pct, fontsizes)

    group_title = {"individual": "Individual defense mechanisms",
                   "risk": "Risk-scoring configs",
                   "all": "All defense configs"}[group]
    fig.suptitle(f"{group_title}: allow / confirm / block outcomes",
                 fontsize=fontsizes["sup_title"], fontweight="bold", color=INK, y=1.03)

    handles, labels = ax1.get_legend_handles_labels()
    fig.legend(handles, labels, fontsize=fontsizes["legend"], frameon=False,
               loc="upper center", bbox_to_anchor=(0.5, 0.02 if poster else -0.02), ncol=3)

    fig.tight_layout()
    out = RESULTS_DIR / f"stacked_{group}.png"
    fig.savefig(out, facecolor="white", bbox_inches="tight")
    print(f"Wrote {out}")


if __name__ == "__main__":
    group = sys.argv[1] if len(sys.argv) > 1 else "all"
    render(group)
