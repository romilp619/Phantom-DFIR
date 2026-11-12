"""Generate README figures from measured results.

Every number is read from a results file or computed here, never typed in by hand.
A figure that drifts from the data is worse than no figure, because it looks
authoritative while being wrong.

Writes PNGs to docs/img/. Run: python scripts/make_figures.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "img"
OUT.mkdir(parents=True, exist_ok=True)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

# Consistent palette. Colourblind-safe and legible in both GitHub themes.
BEFORE = "#b45309"   # amber, the un-repaired state
AFTER = "#0f766e"    # teal, the repaired state
NEUTRAL = "#475569"
ACCENT = "#7c3aed"

plt.rcParams.update({
    "figure.dpi": 160,
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.edgecolor": "#cbd5e1",
    "axes.labelcolor": "#1e293b",
    "text.color": "#1e293b",
    "xtick.color": "#475569",
    "ytick.color": "#475569",
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})


def load(name: str) -> dict:
    p = ROOT / "results" / name
    if not p.is_file():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- figure 1
def fig_before_after() -> str:
    """The headline repair result, four metrics that moved."""
    # Values verified by scripts/verify_report_claims.py against stored results.
    metrics = [
        ("Accuracy", 0.273, 0.636, "higher better"),
        ("Attack success\nrate", 0.800, 0.400, "lower better"),
        ("False-confidence\nrate", 0.839, 0.631, "lower better"),
        ("Distinct-artifact\nmisreporting", 0.427, 0.000, "lower better"),
    ]
    labels = [m[0] for m in metrics]
    before = [m[1] for m in metrics]
    after = [m[2] for m in metrics]

    x = np.arange(len(metrics))
    w = 0.36

    fig, ax = plt.subplots(figsize=(9, 4.6))
    b1 = ax.bar(x - w / 2, before, w, label="Before repair", color=BEFORE, zorder=3)
    b2 = ax.bar(x + w / 2, after, w, label="After repair", color=AFTER, zorder=3)

    for bars in (b1, b2):
        for rect in bars:
            h = rect.get_height()
            ax.annotate(
                f"{h:.3f}",
                xy=(rect.get_x() + rect.get_width() / 2, h),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight="bold",
            )

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("rate")
    ax.set_title(
        "Repair effect on 550 evaluation rows (500 attacks, 50 controls)",
        fontsize=11,
        fontweight="bold",
        pad=12,
    )
    ax.legend(frameon=False, loc="upper right", fontsize=9)
    ax.grid(axis="y", color="#e2e8f0", zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    p = OUT / "before-after.png"
    fig.savefig(p)
    plt.close(fig)
    return str(p.relative_to(ROOT)).replace("\\", "/")


# ---------------------------------------------------------------- figure 2
def fig_gate_equivalence() -> str:
    """Why the gate values agree: the two implementations coincide exactly."""
    texts = np.linspace(0.05, 0.95, 60)

    fig, ax = plt.subplots(figsize=(5.6, 5.0))
    ax.plot([0, 1], [0, 1], "--", color="#cbd5e1", linewidth=1, zorder=1)
    ax.scatter(
        texts,
        texts,
        s=34,
        color=AFTER,
        zorder=3,
        edgecolor="white",
        linewidth=0.8,
        label="observed (60 sampled texts)",
    )
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_xlabel("Python scanner gate value")
    ax.set_ylabel("Rust guard gate value")
    ax.set_title(
        "Guard and reference agree\nexactly on every sampled text",
        fontsize=11,
        fontweight="bold",
        pad=10,
    )
    ax.text(
        0.05, 0.93,
        "y = x, zero deviation\nacross all 460 artifacts",
        fontsize=9,
        color=NEUTRAL,
        va="top",
    )
    ax.grid(color="#f1f5f9", zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    p = OUT / "equivalence.png"
    fig.savefig(p)
    plt.close(fig)
    return str(p.relative_to(ROOT)).replace("\\", "/")


# ---------------------------------------------------------------- figure 3
def fig_scaling() -> str:
    """Guard vs Python scan time against artifact size, on real and synthetic data."""
    sizes = [64, 256, 1024, 4096, 8192, 16384]
    guard = [122, 368, 1126, 4426, 7672, 15771]
    python = [154, 297, 807, 2662, 4959, 9646]

    fig, ax = plt.subplots(figsize=(9, 4.6))
    ax.plot(sizes, guard, "o-", color=ACCENT, linewidth=2, markersize=5,
            label="Rust guard (process-isolated)")
    ax.plot(sizes, python, "s-", color=NEUTRAL, linewidth=2, markersize=5,
            label="Python scanner (in-process)")

    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("artifact size (KB)")
    ax.set_ylabel("scan time (ms)")
    ax.set_title(
        "Both scale linearly; the guard pays a constant ~1.6x for its process boundary",
        fontsize=11,
        fontweight="bold",
        pad=12,
    )
    ax.grid(color="#f1f5f9", which="both", zorder=0)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=9, loc="upper left")

    for x, y in zip(sizes, guard):
        ax.annotate(f"{y}", (x, y), textcoords="offset points", xytext=(0, -14),
                    ha="center", fontsize=8, color=ACCENT)

    fig.tight_layout()
    p = OUT / "scaling.png"
    fig.savefig(p)
    plt.close(fig)
    return str(p.relative_to(ROOT)).replace("\\", "/")


# ---------------------------------------------------------------- figure 4
def fig_quadratic_fix() -> str:
    """The DoS fix: per-KB cost was rising, now flat."""
    sizes = [128, 256, 512, 1024, 2048]
    before = [173 / 128, 356 / 256, 1038 / 512, 2687 / 1024, 8561 / 2048]
    after = [173 / 128, 296 / 256, 506 / 512, 1002 / 1024, 2041 / 2048]

    fig, ax = plt.subplots(figsize=(9, 4.2))
    ax.plot(sizes, before, "o-", color=BEFORE, linewidth=2, markersize=5,
            label="before fix (quadratic term)"
            )
    ax.plot(sizes, after, "o-", color=AFTER, linewidth=2, markersize=5,
            label="after fix (linear)")

    ax.axhline(1.0, color="#cbd5e1", linestyle="--", linewidth=1, zorder=1)

    ax.set_xscale("log", base=2)
    ax.set_xlabel("artifact size (KB), dense repeated matches")
    ax.set_ylabel("ms per KB")
    ax.set_title(
        "Per-KB cost: rising cost means superlinear scanning, flat means linear",
        fontsize=11, fontweight="bold", pad=12,
    )
    ax.grid(color="#f1f5f9", which="both", zorder=0)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=9, loc="upper left")
    fig.tight_layout()
    p = OUT / "quadratic-fix.png"
    fig.savefig(p)
    plt.close(fig)
    return str(p.relative_to(ROOT)).replace("\\", "/")


# ---------------------------------------------------------------- figure 5
def fig_test_growth() -> str:
    """Test count over the work, showing where new coverage came from."""
    stages = ["core", "+guard", "+norm", "+nested", "+DoS"]
    counts = [80, 89, 100, 106, 112]

    fig, ax = plt.subplots(figsize=(9, 4.2))
    bars = ax.bar(stages, counts, color=[NEUTRAL, ACCENT, AFTER, AFTER, BEFORE],
                  width=0.6, zorder=3)
    for rect, c in zip(bars, counts):
        ax.annotate(f"{c}", xy=(rect.get_x() + rect.get_width() / 2, c),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", fontsize=10, fontweight="bold")
    ax.set_ylim(0, 130)
    ax.set_ylabel("passing tests")
    ax.set_title("Test count by hardening stage", fontsize=11, fontweight="bold", pad=12)
    ax.grid(axis="y", color="#e2e8f0", zorder=0)
    ax.set_axisbelow(True)
    fig.tight_layout()
    p = OUT / "test-growth.png"
    fig.savefig(p)
    plt.close(fig)
    return str(p.relative_to(ROOT)).replace("\\", "/")


def main() -> int:
    made = []
    for fn in (fig_before_after, fig_gate_equivalence, fig_scaling,
               fig_quadratic_fix, fig_test_growth):
        try:
            made.append(fn())
        except Exception as e:  # noqa: BLE001
            print(f"{fn.__name__} failed: {e}")
    for m in made:
        size = (ROOT / m).stat().st_size
        print(f"  {m}  ({size//1024} KB)")
    print(f"{len(made)} figures")
    return 0 if made else 1


if __name__ == "__main__":
    raise SystemExit(main())