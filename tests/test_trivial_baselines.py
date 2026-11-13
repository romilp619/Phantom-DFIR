"""The constant-predictor baselines are computed from the rows, and the repaired
verifier has to beat the best of them, otherwise its score means nothing."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phantom_ai_safety.evaluation.comparison import run_improved  # noqa: E402
from phantom_ai_safety.evaluation.metrics import score_outcomes, trivial_baselines  # noqa: E402
from phantom_ai_safety.red_team.rows import build_eval_set  # noqa: E402


def test_trivial_baselines_are_computed_from_the_rows():
    rows = build_eval_set(per_family=50, seed=1729)
    base = trivial_baselines(rows)
    assert set(base) == {"always_CONFIRMED", "always_NEEDS_MORE", "always_REFUTED", "always_CLEARED"}
    needs_more = base["always_NEEDS_MORE"]
    # 316 of 550 gold labels are NEEDS_MORE; 4 of 10 attack families have another gold.
    assert round(needs_more["accuracy"], 3) == 0.575
    assert round(needs_more["attack_success_rate"], 3) == 0.400
    assert round(needs_more["capability_retention"], 3) == 0.320
    # A smaller set gives different values: nothing here is a stored constant.
    small = trivial_baselines(build_eval_set(per_family=3, seed=1729))
    assert small["always_NEEDS_MORE"]["capability_retention"] != needs_more["capability_retention"]


def test_grounded_verifier_beats_every_constant_predictor():
    rows = build_eval_set(per_family=50, seed=1729)
    after = score_outcomes(run_improved(rows))
    for name, base in trivial_baselines(rows).items():
        assert after["accuracy"] > base["accuracy"], name
        assert after["attack_success_rate"] < base["attack_success_rate"], name
        assert after["capability_retention"] > base["capability_retention"], name
