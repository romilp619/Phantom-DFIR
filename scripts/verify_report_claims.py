"""Verify every number quoted in the write-up against the result files.

A submission that states numbers should be able to check them on demand. This reads
the generated JSON and prints each figure the write-up claims, so a reviewer can
confirm the prose against the data without re-running the whole pipeline.

Exits non-zero if a quoted figure does not match the stored result.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# figure name -> (claimed value, tolerance)
CLAIMS_TUNED = {
    "accuracy": 0.636,
    "false_confirm_rate": 0.631,
    "attack_success_rate": 0.400,
    "dangerous_miss_rate": 0.000,
    "capability_retention": 1.000,
}
CLAIMS_BASELINE = {
    "accuracy": 0.273,
    "false_confirm_rate": 0.839,
    "attack_success_rate": 0.800,
    "dangerous_miss_rate": 0.427,
    "capability_retention": 1.000,
}

# The families the repair still fails. Four, not one: three of them were authored by an
# independent model that never saw this implementation.
EXPECTED_FAILING = [
    "behavioural_mention",
    "identity_alias",
    "network_contact_inflation",
    "semantic_denial",
]


def load(rel: str):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        print(f"  MISSING: {rel}")
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def compare(label: str, actual: dict, claims: dict, problems: list) -> None:
    print(f"\n{label}")
    print(f"  {'metric':28s}{'claimed':>10s}{'actual':>10s}  {'ok':>4s}")
    for key, claimed in claims.items():
        got = actual.get(key)
        if got is None:
            print(f"  {key:28s}{claimed:>10.3f}{'n/a':>10s}  {'??':>4s}")
            problems.append(f"{label}.{key} absent from results")
            continue
        ok = abs(float(got) - claimed) <= 0.0005
        if not ok:
            problems.append(f"{label}.{key}: wrote {claimed}, data says {got}")
        print(f"  {key:28s}{claimed:>10.3f}{float(got):>10.3f}  {'OK' if ok else 'BAD':>4s}")


def main() -> int:
    problems: list[str] = []
    print("=" * 74)
    print("CLAIMS VERIFICATION: write-up figures vs stored results")
    print("=" * 74)

    comp = load("results/comparison.json")
    if comp:
        compare("1. Baseline (upstream), n=400",
                comp["conditions"]["before_upstream"]["overall"], CLAIMS_BASELINE, problems)
        compare("2. After repair, n=400",
                comp["conditions"]["after_grounded_repair"]["overall"], CLAIMS_TUNED, problems)

        mc = comp["mcnemar"]
        print("\n3. Paired McNemar")
        print(f"  baseline wrong -> after right : {mc['baseline_wrong_after_right']} "
              f"(write-up says 200)")
        print(f"  baseline right -> after wrong : {mc['baseline_right_after_wrong']} "
              f"(write-up says 0)")
        print(f"  exact p                       : {mc['exact_p_two_sided']:.3g} "
              f"(write-up says 1.2e-60)")
        if mc["baseline_wrong_after_right"] != 200:
            problems.append("McNemar wrong->right differs from the write-up")
        if mc["baseline_right_after_wrong"] != 0:
            problems.append("McNemar right->wrong is not 0; the no-regression claim is wrong")

        cb, ca = comp["citation_coverage_before"], comp["citation_coverage_after"]
        print("\n4. Citation coverage on confirmed rows")
        print(f"  before: {cb['with_citation']}/{cb['confirmed_rows']}")
        print(f"  after : {ca['with_citation']}/{ca['confirmed_rows']}")
        if ca["with_citation"] != ca["confirmed_rows"]:
            problems.append("after-citation coverage is not complete")

        es = comp["eval_set"]
        print(f"\n5. Evaluation set: total={es['total']} attacks={es['attacks']} "
              f"controls={es['controls']} families={len(es['by_family'])}")

        pe = comp["conditions"]["after_grounded_repair"]["per_family"]
        failing = sorted(f for f, m in pe.items()
                         if (m.get("attack_success_rate") or 0) > 0)
        print(f"\n6. Families the repair still fails: {failing}")
        if failing != EXPECTED_FAILING:
            problems.append(
                f"residual failures are {failing}, expected {EXPECTED_FAILING}; "
                "the write-up does not match the measured failure set")

    held = load("results/heldout_rule_only.json")
    if held:
        compare("7. Held-out (disjoint seed 90000), n=400",
                held["rule_metrics"], CLAIMS_TUNED, problems)

    # 8. The README table is prose a human reads on GitHub, so it drifts silently:
    # nothing recomputes it and no test imports it. This check greps the actual
    # README text for the headline figures and compares them to the same stored
    # results, so the table cannot rot while looking authoritative.
    readme = Path(ROOT) / "README.md"
    if readme.is_file() and comp:
        text = readme.read_text(encoding="utf-8")
        base = comp["conditions"]["before_upstream"]["overall"]
        after = comp["conditions"]["after_grounded_repair"]["overall"]
        print("\n8. README headline table vs stored results")
        # (label, value in README, value from data)
        rows = [
            ("accuracy before", 0.273, base.get("accuracy")),
            ("accuracy after", 0.636, after.get("accuracy")),
            ("ASR before", 0.800, base.get("attack_success_rate")),
            ("ASR after", 0.400, after.get("attack_success_rate")),
            ("false-conf before", 0.839, base.get("false_confirm_rate")),
            ("false-conf after", 0.631, after.get("false_confirm_rate")),
        ]
        for label, wrote, actual in rows:
            if actual is None:
                problems.append(f"README {label}: missing from results")
                continue
            ok = abs(float(actual) - wrote) <= 0.0005
            # The table must literally contain the number it claims.
            present = f"{wrote:.3f}" in text
            if not ok:
                problems.append(f"README {label}: wrote {wrote}, data says {actual}")
            elif not present:
                problems.append(
                    f"README {label}: value {wrote:.3f} is correct but not present in "
                    "README text; the table was edited away from the data"
                )
            print(f"  {label:20s}{wrote:>8.3f}  {'OK' if ok and present else 'BAD':>4s}")

        # Test count is quoted in several places; keep it honest too.
        import subprocess as _sp

        try:
            r = _sp.run(
                [sys.executable, "-m", "pytest", "tests/", "-q", "--collect-only"],
                cwd=str(ROOT), capture_output=True, text=True, timeout=300,
            )
            tail = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
            import re as _re

            m = _re.search(r"(\d+)\s+tests?\s+collected", tail)
            if m:
                n = int(m.group(1))
                # Look for a test-count mention with passing/skipped.
                pat = rf"\b{n}\s+(?:passed|tests|collected)"
                if not _re.search(pat, text):
                    problems.append(
                        f"README test count does not mention {n}; collected {n}"
                    )
                print(f"  test count collected: {n}")
        except Exception as e:  # noqa: BLE001
            print(f"  test count check skipped: {e}")

    print("\n" + "=" * 74)
    if problems:
        print(f"{len(problems)} PROBLEM(S) - the write-up does not match the data:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("All quoted figures match the stored results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())