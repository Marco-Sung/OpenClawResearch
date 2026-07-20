# two_agent/make_compiled_chart.py
#
# Renders two_agent_compiled.csv (built by aggregate_repeats.py) as a
# 100%-stacked allow/confirm/block chart, one panel per channel, with
# two/three/hybrid as the compared bars within each panel -- so you can see
# directly whether adding the verifier stage, or hybridizing with risk_llm,
# actually changes outcomes. Same status-color language as the main defense
# charts (tests/diagnostics/make_stacked_chart.py) for visual consistency
# across the paper.
#
#   python -m two_agent.make_compiled_chart

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patheffects as pe
import matplotlib.patches as mpatches

COMPILED_CSV = Path(__file__).resolve().parent / "results" / "two_agent_compiled.csv"
OUT_PNG = Path(__file__).resolve().parent / "results" / "two_agent_compiled_chart.png"

GOOD, WARNING, CRITICAL, INK = "#0ca30c", "#fab219", "#d03b3b", "#0b0b0b"
MODE_ORDER = ["two", "three", "hybrid"]
MODE_LABEL = {"two": "2-agent", "three": "3-agent", "hybrid": "hybrid\n(+risk_llm)"}


def load_rows():
    with open(COMPILED_CSV) as f:
        return list(csv.DictReader(f))


def draw_panel(ax, rows, key_prefix, title):
    modes = [m for m in MODE_ORDER if any(r["mode"] == m for r in rows)]
    x = range(len(modes))
    bottoms = [0.0] * len(modes)

    for color, label, field in [(GOOD, "Allow", "allow"), (WARNING, "Confirm", "confirm"),
                                 (CRITICAL, "Block", "block")]:
        heights = []
        for m in modes:
            row = next((r for r in rows if r["mode"] == m), None)
            if row is None:
                heights.append(0.0)
                continue
            n = int(row[f"{key_prefix}_n"]) or 1
            heights.append(int(row[f"{key_prefix}_{field}"]) / n * 100)
        bars = ax.bar(list(x), heights, bottom=bottoms, width=0.6, color=color,
                       label=label, edgecolor="white", linewidth=1.2, zorder=3)
        for i, (b, h) in enumerate(zip(bars, heights)):
            if h >= 5:
                txt = ax.text(b.get_x() + b.get_width() / 2, bottoms[i] + h / 2, f"{h:.0f}%",
                               ha="center", va="center", fontsize=11, fontweight="bold",
                               color=INK, zorder=4)
                txt.set_path_effects([pe.withStroke(linewidth=2, foreground="white")])
        bottoms = [bo + h for bo, h in zip(bottoms, heights)]

    ax.set_ylim(0, 100)
    ax.set_xticks(list(x))
    ax.set_xticklabels([MODE_LABEL[m] for m in modes], fontsize=10, color=INK)
    ax.set_title(title, fontsize=12, fontweight="bold", color=INK, pad=8)
    ax.tick_params(axis="y", labelsize=9, colors="#5b616f")
    ax.tick_params(axis="x", length=0)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color("#d8d7d0")
    ax.yaxis.grid(True, color="#eeeeea", linewidth=1, zorder=0)
    ax.set_axisbelow(True)


def main():
    rows = load_rows()
    channels = sorted(set(r["channel"] for r in rows))

    fig, axes = plt.subplots(2, len(channels), figsize=(3.6 * len(channels), 7), dpi=300)
    fig.patch.set_facecolor("white")

    for col, channel in enumerate(channels):
        crows = [r for r in rows if r["channel"] == channel]
        ax_a, ax_b = axes[0][col], axes[1][col]
        for ax in (ax_a, ax_b):
            ax.set_facecolor("white")
        draw_panel(ax_a, crows, "attack", f"{channel}\nattacks")
        draw_panel(ax_b, crows, "benign", f"{channel}\nbenign")

    fig.suptitle("two_agent: allow / confirm / block by mode, per channel",
                  fontsize=16, fontweight="bold", color=INK, y=1.02)
    handles = [mpatches.Patch(facecolor=GOOD, label="Allow"),
               mpatches.Patch(facecolor=WARNING, label="Confirm"),
               mpatches.Patch(facecolor=CRITICAL, label="Block")]
    fig.legend(handles=handles, fontsize=11, frameon=False, loc="upper center",
               bbox_to_anchor=(0.5, -0.01), ncol=3)

    fig.tight_layout()
    fig.savefig(OUT_PNG, facecolor="white", bbox_inches="tight")
    print(f"Wrote {OUT_PNG}")


if __name__ == "__main__":
    main()
