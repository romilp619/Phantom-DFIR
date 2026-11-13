"""Verify the Rust guard still agrees with the Python scanner after normalisation.

Normalisation is a Python-side addition. The Rust guard mirrors the raw rules only.
This script confirms the two still agree on every artifact, which is the property the
test suite depends on, and reports whether normalisation changed anything on the
lexical attack corpus.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phantom_ai_safety.evidence_scanner import guard, scanner  # noqa: E402
from phantom_ai_safety.red_team.injection import build_injection_set  # noqa: E402


def main() -> int:
    if not guard.available():
        print("guard not built")
        return 2

    rows = build_injection_set(per_family=20)
    items = [(i.artifact_id, i.text) for r in rows for i in r.presented_evidence]

    decisive_mismatch = []
    count_mismatch = []
    normalisation_added = 0

    for aid, text in items:
        exp = scanner.scan_artifact(aid, text)
        got = guard.scan_artifact(aid, text)

        if exp.is_manipulated != got.is_manipulated:
            decisive_mismatch.append(aid)
        if exp.highest_severity != got.highest_severity:
            decisive_mismatch.append(aid)
        if len(exp.findings) != len(got.findings):
            count_mismatch.append((aid, len(exp.findings), len(got.findings)))
        # Did normalisation contribute any finding? Derived findings carry offset -1.
        if any(f.char_offset == -1 for f in exp.findings):
            normalisation_added += 1

    print(f"corpus artifacts            : {len(items)}")
    print(f"decisive mismatches         : {len(decisive_mismatch)}")
    print(f"finding-count mismatches    : {len(count_mismatch)}")
    print(f"artifacts where normalisation added findings: {normalisation_added}")
    print()

    if decisive_mismatch:
        print("DECISIVE MISMATCHES (is_manipulated or severity differ):")
        for a in decisive_mismatch[:10]:
            print(f"  {a}")
        return 1

    if count_mismatch:
        print("Finding-count differences (normalisation adds findings on the python side):")
        for a, py_n, rs_n in count_mismatch[:10]:
            print(f"  {a}: python={py_n} rust={rs_n}")
        print()
        print("This is expected and safe: normalisation can only ADD findings. Decisive")
        print("verdicts (is_manipulated, severity) still agree, which is what the guard")
        print("equivalence test asserts.")
        return 0

    print("guard and scanner agree on every artifact, including finding counts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())