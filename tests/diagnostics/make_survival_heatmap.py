# tests/diagnostics/make_survival_heatmap.py
#
# Renders the standalone parser-survival matrix (survival_matrix.build_matrix,
# defense-agnostic -- see survival_matrix.py) as a heatmap: one panel per
# channel (email/web/file), rows = attacks, columns = extractors, cell color
# = did the malicious content survive parsing. Status colors (green = died/
# safe, red = survived/leaked), with a direct symbol in every cell so
# identity never depends on color alone. Gray = not applicable (the file
# channel's extractors are format-specific, so not every attack has every
# column).
#
#   venv/bin/python -m tests.diagnostics.make_survival_heatmap

import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "openclaw-security"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from tests.diagnostics.survival_matrix import build_matrix
from tests.attacks.email import EMAIL_ATTACKS
from tests.attacks.web import WEB_ATTACKS
from tests.attacks.file import FILE_ATTACKS

RESULTS_DIR = Path.home() / "openclaw-security" / "results"

GOOD = "#0ca30c"       # died -- safe
CRITICAL = "#d03b3b"   # survived -- leaked
NA_GRAY = "#e3e2dc"
INK = "#0b0b0b"

CHANNELS = {
    "email": {"attacks": EMAIL_ATTACKS, "columns": ["plaintext_only", "all_parts"]},
    "web": {"attacks": WEB_ATTACKS,
            "columns": ["naive_regex", "bs4_get_text", "bs4_visible_only", "css_aware"]},
    "file": {"attacks": FILE_ATTACKS,
             "columns": ["txt", "pdf_naive", "pdf_color_filtered", "docx_naive", "docx_visible_only"]},
}

COLUMN_LABEL = {
    "plaintext_only": "plaintext\nonly", "all_parts": "all\nparts",
    "naive_regex": "naive\nregex", "bs4_get_text": "bs4\nget_text",
    "bs4_visible_only": "bs4\nvisible", "css_aware": "css_aware\n(new)",
    "txt": "txt", "pdf_naive": "pdf\nnaive", "pdf_color_filtered": "pdf color\nfiltered",
    "docx_naive": "docx\nnaive", "docx_visible_only": "docx\nvisible",
}


def short_name(attack_name, channel):
    """Wrap onto 2 lines so long web/email attack names (up to 32 chars)
    don't hang far enough left to crowd the neighboring panel."""
    words = attack_name.replace(f"{channel}_", "").replace("_", " ").split()
    mid = len(words) // 2 + len(words) % 2
    return " ".join(words[:mid]) + "\n" + " ".join(words[mid:])


def draw_panel(ax, channel, lookup):
    info = CHANNELS[channel]
    attacks = [a["name"] for a in info["attacks"]]
    columns = info["columns"]

    for yi, attack in enumerate(attacks):
        for xi, col in enumerate(columns):
            key = (attack, col)
            cell = lookup.get(key)
            y = len(attacks) - 1 - yi
            if cell is None:
                color, label = NA_GRAY, ""
            elif cell["survives"]:
                color, label = CRITICAL, "✗"   # survived (leaked)
            else:
                color, label = GOOD, "✓"        # died (safe)
            rect = plt.Rectangle((xi, y), 0.94, 0.94, facecolor=color,
                                  edgecolor="white", linewidth=1.5, zorder=2)
            ax.add_patch(rect)
            if label:
                ax.text(xi + 0.47, y + 0.47, label, ha="center", va="center",
                        fontsize=15, fontweight="bold", color="white", zorder=3)
            if cell is not None and cell["assigned"]:
                ax.add_patch(plt.Rectangle((xi, y), 0.94, 0.94, facecolor="none",
                                            edgecolor=INK, linewidth=2.4, zorder=4))

    ax.set_xlim(0, len(columns))
    ax.set_ylim(0, len(attacks))
    ax.set_xticks([i + 0.47 for i in range(len(columns))])
    ax.set_xticklabels([COLUMN_LABEL.get(c, c) for c in columns], fontsize=9.5, color=INK)
    ax.set_yticks([len(attacks) - 1 - i + 0.47 for i in range(len(attacks))])
    ax.set_yticklabels([short_name(a, channel) for a in attacks], fontsize=9.5,
                        color=INK, linespacing=1.3)
    ax.set_title(channel.capitalize(), fontsize=15, fontweight="bold", color=INK, pad=10)
    ax.set_aspect("equal")
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)


def main():
    rows = build_matrix()
    lookup = {(r["attack"], r["extractor"]): r for r in rows if r["error"] is None}

    fig, axes = plt.subplots(
        1, 3, figsize=(17.5, 6.5), dpi=300,
        gridspec_kw={"width_ratios": [2.1, 5.0, 5.2], "wspace": 0.9},
    )
    fig.patch.set_facecolor("white")
    for ax, channel in zip(axes, ["email", "web", "file"]):
        ax.set_facecolor("white")
        draw_panel(ax, channel, lookup)

    fig.suptitle("Parser survival matrix: does the malicious content survive extraction?",
                  fontsize=17, fontweight="bold", color=INK, y=1.04)

    handles = [
        mpatches.Patch(facecolor=GOOD, edgecolor="white", label="✓ died (safe)"),
        mpatches.Patch(facecolor=CRITICAL, edgecolor="white", label="✗ survived (leaked)"),
        mpatches.Patch(facecolor=NA_GRAY, edgecolor="white", label="not applicable"),
        mpatches.Patch(facecolor="white", edgecolor=INK, linewidth=2, label="assigned extractor"),
    ]
    fig.legend(handles=handles, fontsize=11.5, frameon=False, loc="upper center",
               bbox_to_anchor=(0.5, 0.02), ncol=4)

    fig.tight_layout()
    out = RESULTS_DIR / "survival_heatmap.png"
    fig.savefig(out, facecolor="white", bbox_inches="tight")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
