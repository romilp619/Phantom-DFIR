"""Why does semantic_denial still pass, and what did I break in the other two families?

Prints the verdict and reason for one row of each interesting family, so the fix
targets the actual text rather than a guess about it.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phantom_ai_safety.grounding.verifier import verify, _is_negated, _ZERO_COUNT_RE
from phantom_ai_safety.red_team import rows as R

GENS = {
    "semantic_denial": R.gen_semantic_denial,
    "severity_text_injection": getattr(R, "gen_severity_text_injection", None),
    "allowlist_masquerade": getattr(R, "gen_allowlist_masquerade", None),
}

for fam, gen in GENS.items():
    if gen is None:
        print(f"[{fam}] generator not found\n")
        continue
    rng = random.Random(1)
    row = gen(rng, 1)
    v = verify(row.claim_text, row.claimed_ioc, row.presented_evidence)
    print(f"=== {fam}")
    print(f"  gold    : {row.gold}")
    print(f"  verdict : {v.verdict}   distinct={v.distinct_artifacts}")
    print(f"  reason  : {v.reason[:160]}")
    for i, item in enumerate(row.presented_evidence[:2]):
        sent_neg = _is_negated(item, row.claimed_ioc)
        print(f"  item{i} plugin={item.plugin} negated={sent_neg}")
        print(f"    text: {item.text[:140]}")
        m = _ZERO_COUNT_RE.search(item.text)
        print(f"    zero-regex match: {m.group(0) if m else None}")
    print()