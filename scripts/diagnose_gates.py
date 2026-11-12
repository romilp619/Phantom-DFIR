"""Why do legitimate CONFIRMED families now abstain?

Prints every presented item for the regressed families with each gate's verdict, so
the suppressing condition is identified rather than guessed.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phantom_ai_safety.grounding import verifier as V
from phantom_ai_safety.red_team import rows as R

CASES = [
    ("severity_text_injection", getattr(R, "gen_severity_text_injection", None)),
    ("allowlist_masquerade", getattr(R, "gen_allowlist_masquerade", None)),
    ("clean_control", getattr(R, "gen_clean_control", None)),
    ("behavioural_mention", R.gen_behavioural_mention),
]

for fam, gen in CASES:
    if gen is None:
        print(f"[{fam}] no generator\n")
        continue
    row = gen(random.Random(1), 1)
    print(f"=== {fam}   gold={row.gold}  ioc={row.claimed_ioc}")
    for item in row.presented_evidence:
        ment = V._mentions(item.text, row.claimed_ioc)
        beh = item.plugin in V.BEHAVIOURAL_PLUGINS
        neg = V._is_negated(item, row.claimed_ioc) if ment else False
        ben = V._BENIGN_OBSERVATION_RE.search(V._sentence_around(item.text, row.claimed_ioc))
        inc = V._is_incriminating(item, row.claimed_ioc) if ment else False
        keep = ment and beh and not neg and inc
        print(f"  plugin={item.plugin:<14} mention={ment} behav={beh} neg={neg} "
              f"benign_re={bool(ben)} incrim={inc} -> KEEP={keep}")
        print(f"    id={item.artifact_id!r}")
        print(f"    canon={V._canonical_identity(item.artifact_id, item.text)!r}")
        print(f"    text={item.text[:110]!r}")
        if ben:
            print(f"    benign pattern matched: {ben.group(0)!r}")
    v = V.verify(row.claim_text, row.claimed_ioc, row.presented_evidence)
    print(f"  VERDICT={v.verdict} distinct={v.distinct_artifacts}")
    print()