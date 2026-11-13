"""Why do two families fail on the held-out seed but pass on the tuned seed?

A result that changes with the seed is either a real weakness in the repair or a
defect in the evaluation rows. Both matter, and the difference decides whether the
held-out numbers can be reported at all.

Diagnoses by generating the same family under both seed bases and comparing, for each
row, the gold label against exactly what the verifier sees: how many distinct
artifacts there are, which plugins they carry, and whether the claimed indicator
appears in their text.

    python scripts/diagnose_seed_split.py
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
if PKG_ROOT not in sys.path:
    sys.path.insert(0, PKG_ROOT)

from phantom_ai_safety.grounding.verifier import (  # noqa: E402
    BEHAVIOURAL_PLUGINS,
    _behavioural_support,
    _mentions_anywhere,
    verify,
)
from phantom_ai_safety.red_team.rows import GENERATORS  # noqa: E402
from phantom_ai_safety.repair.dataset import HELDOUT_SEED_BASE, TRAIN_SEED_BASE  # noqa: E402

import random  # noqa: E402


def rows_for(family: str, seed_base: int, n: int = 6):
    rng = random.Random(seed_base + list(GENERATORS).index(family))
    return [GENERATORS[family](rng, i) for i in range(n)]


def describe(row) -> str:
    mentioned = _mentions_anywhere(row.presented_evidence, row.claimed_ioc)
    behavioural = _behavioural_support(row.presented_evidence, row.claimed_ioc)
    plugins = sorted({e.plugin for e in row.presented_evidence})
    behavioural_plugins = sorted({e.plugin for e in behavioural})
    v = verify(row.claim_text, row.claimed_ioc, row.presented_evidence)
    return (
        f"    keys={len(row.verified_sources)} distinct_artifacts={row.distinct_artifacts} "
        f"plugins={plugins}\n"
        f"      behavioural_plugins={behavioural_plugins} "
        f"mentioned={len(mentioned)} behavioural={len(behavioural)}\n"
        f"      gold={row.gold:12s} verdict={v.verdict:12s} "
        f"{'MATCH' if v.verdict == row.gold else '*** MISMATCH ***'}\n"
        f"      ioc={row.claimed_ioc!r}\n"
        f"      claim={row.claim_text[:88]!r}"
    )


def main() -> int:
    families = ["count_inflation", "alias_reuse", "behavioural_mention", "clean_control"]
    for family in families:
        print("=" * 78)
        print(f"FAMILY: {family}")
        print("=" * 78)
        for label, base in (("TRAIN seed", TRAIN_SEED_BASE), ("HELDOUT seed", HELDOUT_SEED_BASE)):
            print(f"\n  {label} (base {base}):")
            for row in rows_for(family, base):
                print(describe(row))
                print()
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())