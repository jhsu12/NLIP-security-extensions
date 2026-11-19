"""Figures 2 and 3 of the paper.

    python -m paper.make_figures       # writes paper/figures/off_vs_on.pdf and detection.pdf

Figure 2: attack success and task success, no guard vs ToolGuard (held-out test split).
Figure 3: precision, recall and F1 of the guard's two checks (E17 judge calls, E16 scanner).

Data: the same results files as paper/make_tables.py (E11/E14 no guard, E17 d3_only).
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from paper.make_tables import MODELS, POISONING, SHORT, count, detection_scores, files, fmt_score, group  # noqa: E402
from adversarial_tests.tool_guard_eval.metrics import load  # noqa: E402

OUT = Path(__file__).resolve().parent / "figures" / "off_vs_on.pdf"

# Categorical slots 1-2 of the reference palette (validated: CVD ΔE 24.7, contrast ≥ 3:1).
OFF = "#eb6834"
ON = "#2a78d6"
INK = "#1f1f1e"
MUTED = "#6b6a63"
GRID = "#e4e3de"
ATTACK_LABELS = {
    "tool_poisoning": "Tool desc.\n<IMPORTANT>",
    "tool_poisoning_plain": "Tool desc.\nplain",
    "schema_poisoning_tagged": "Param. desc.\n<IMPORTANT>",
}


def main() -> None:
    none_records = load(files("none__*__test.jsonl") + files("none__*__test__probe.jsonl"))
    final_records = load(files("d3_only__*__test__d3final.jsonl"))

    groups = [(attack, model) for attack in POISONING for model in MODELS]
    data = {}
    for attack, model in groups:
        off = group(none_records, "none", model, attack)
        on = group(final_records, "d3_only", model, attack)
        data[attack, model] = {
            "asr": (count(r["attack_success"] for r in off), count(r["attack_success"] for r in on)),
            "util": (count(r["utility"] for r in off), count(r["utility"] for r in on)),
        }

    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.size": 7,
            "pdf.fonttype": 42,
            "axes.edgecolor": MUTED,
            "axes.labelcolor": INK,
            "xtick.color": MUTED,
            "ytick.color": MUTED,
            "text.color": INK,
        }
    )
    fig, (ax_asr, ax_util) = plt.subplots(2, 1, figsize=(3.33, 2.1), sharex=True)
    width = 0.38
    positions = []
    for index, _ in enumerate(groups):
        # A small gap between attack types so the three model pairs read as groups.
        positions.append(index + 0.35 * (index // len(MODELS)))

    for ax, metric, ylabel, limit in (
        (ax_asr, "asr", "Hijacked cases\n(of 150)", 25),
        (ax_util, "util", "User task done\nunder attack (%)", 100),
    ):
        for offset, side, color, hatch, label in (
            (-width / 2, 0, OFF, "////", "No guard"),
            (width / 2, 1, ON, None, "ToolGuard"),
        ):
            values = [
                data[g][metric][side][0] if metric == "asr" else 100 * data[g][metric][side][0] / data[g][metric][side][1]
                for g in groups
            ]
            bars = ax.bar(
                [p + offset for p in positions],
                values,
                width,
                color=color,
                edgecolor="white",
                linewidth=0.8,
                hatch=hatch,
                label=label,
                zorder=2,
            )
            if metric == "asr":
                # Episodes hijacked out of 150, directly on each bar.
                for bar, g in zip(bars, groups):
                    hits = data[g][metric][side][0]
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + 0.5,
                        str(hits),
                        ha="center",
                        va="bottom",
                        fontsize=6,
                        color=INK if hits else ON,
                        fontweight="normal" if hits else "bold",
                    )
        ax.set_ylim(0, limit)
        ax.set_ylabel(ylabel)
        ax.grid(axis="y", color=GRID, linewidth=0.5, zorder=0)
        ax.spines[["top", "right"]].set_visible(False)
        ax.tick_params(length=2, width=0.5)

    ax_util.set_yticks([0, 25, 50, 75, 100])
    ax_asr.set_yticks([0, 5, 10, 15, 20, 25])
    ax_util.set_xticks(positions, [SHORT[m] for _, m in groups])
    for start in range(0, len(groups), len(MODELS)):
        centre = sum(positions[start : start + len(MODELS)]) / len(MODELS)
        ax_util.annotate(
            ATTACK_LABELS[groups[start][0]],
            xy=(centre, 0),
            xycoords=("data", "axes fraction"),
            xytext=(0, -14),
            textcoords="offset points",
            ha="center",
            va="top",
            fontsize=6.5,
            color=INK,
        )
    ax_asr.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), frameon=False, ncol=2, handlelength=1.2, columnspacing=1.0)
    fig.tight_layout(h_pad=0.6)
    fig.subplots_adjust(bottom=0.2)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT)
    fig.savefig(OUT.with_suffix(".png"), dpi=200)
    print(f"wrote {OUT}")
    detection_figure(final_records)


# Categorical slots 1-3 (validated; aqua is under 3:1 contrast, so every bar is labelled).
METRICS = (("precision", "Precision", "#2a78d6"), ("recall", "Recall", "#eb6834"), ("f1", "F1", "#1baf7a"))


def detection_figure(final_records) -> None:
    rows = detection_scores(final_records)
    fig, ax = plt.subplots(figsize=(3.33, 1.6))
    width = 0.26
    for index, (key, label, color) in enumerate(METRICS):
        xs = [g + (index - 1) * width for g in range(len(rows))]
        values = [counts[key] for _, counts in rows]
        bars = ax.bar(xs, values, width, color=color, edgecolor="white", linewidth=0.8, label=label, zorder=2)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 0.015, fmt_score(value), ha="center", va="bottom",
                    fontsize=5, color=INK, rotation=90)
    ax.set_xticks(range(len(rows)), [label.replace(": ", ":\n").replace(" (d3)", "\n(d3)") for label, _ in rows])
    ax.set_ylim(0, 1.42)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.grid(axis="y", color=GRID, linewidth=0.5, zorder=0)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(length=2, width=0.5)
    ax.axvline(1.5, color=MUTED, linewidth=0.5, linestyle=":")
    ax.text(0.5, 1.3, "final design", ha="center", fontsize=6, color=MUTED)
    ax.text(2.5, 1.3, "ablations", ha="center", fontsize=6, color=MUTED)
    ax.legend(loc="upper center", frameon=False, ncol=3, handlelength=1.2, columnspacing=1.0, bbox_to_anchor=(0.5, 1.2))
    fig.tight_layout()
    out = OUT.with_name("detection.pdf")
    fig.savefig(out)
    fig.savefig(out.with_suffix(".png"), dpi=200)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
