"""Run the Rust guard over the red-team attack corpus and report what it caught.

This is the evidence that the compiled scanner is not a decoration: it is measured
against the same generated attacks the Python evaluation uses, and the report states
plainly when the two disagree.

Usage:
    python scripts/run_rust_guard.py [--write]

--write saves results/rust_guard_report.json and exits non-zero if the guard and the
reference scanner disagree on any artifact.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phantom_ai_safety.evidence_scanner import guard, scanner  # noqa: E402
from phantom_ai_safety.red_team.injection import build_injection_set  # noqa: E402

RESULTS = ROOT / "results" / "rust_guard_report.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="write the JSON report")
    ap.add_argument("--per-family", type=int, default=20, help="attacks per family")
    args = ap.parse_args()

    if not guard.available():
        print("phantom-guard binary not found.")
        print("Build it:  cd phantom-guard && cargo build --release")
        return 2

    manifest = guard.manifest()
    print("=== guard identity ===")
    print(f"  version           : {manifest['version']}")
    print(f"  rules / patterns  : {manifest['rules']} / {manifest['patterns']}")
    print(f"  rule fingerprint  : {manifest['rule_fingerprint'][:32]}...")
    print(f"  memory safe       : {manifest['memory_safe']}")
    print(f"  boundary          : {manifest['boundary']}")
    print()

    print("=== built-in self-test ===")
    ok, out = guard.self_test()
    for line in out.splitlines():
        print("  " + line)
    if not ok:
        print("SELF-TEST FAILED")
        return 1
    print()

    rows = build_injection_set(per_family=args.per_family)
    # Flatten to the artifacts that actually reach the model.
    items: list[tuple[str, str]] = []
    for row in rows:
        for item in row.presented_evidence:
            items.append((item.artifact_id, item.text))

    print(f"=== scanning {len(items)} artifacts from {len(rows)} attack rows ===")
    rust_results = guard.scan_evidence(items)
    rust_summary = guard.summarize(rust_results)

    print(f"  artifacts scanned      : {rust_summary['artifacts_scanned']}")
    print(f"  flagged as manipulated : {rust_summary['artifacts_manipulated']}")
    print(f"  total findings         : {rust_summary['total_findings']}")
    print()
    print("  by severity:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        print(f"    {sev:<9}: {rust_summary['by_severity'].get(sev, 0)}")
    print()
    print("  by category:")
    for cat, n in sorted(rust_summary["by_category"].items(), key=lambda kv: -kv[1]):
        print(f"    {cat:<28}: {n}")
    print()

    # Equivalence against the reference implementation. This is the claim that makes
    # the guard trustworthy, so it is checked here rather than asserted in prose.
    print("=== equivalence with python scanner ===")
    mismatches = []
    for (aid, text), got in zip(items, rust_results):
        exp = scanner.scan_artifact(aid, text)
        if (
            exp.is_manipulated != got.is_manipulated
            or exp.highest_severity != got.highest_severity
            or exp.artifact_sha256 != got.artifact_sha256
            or exp.length != got.length
            or len(exp.findings) != len(got.findings)
        ):
            mismatches.append(aid)
    if mismatches:
        print(f"  DISAGREEMENT on {len(mismatches)} of {len(items)} artifacts")
        for aid in mismatches[:10]:
            print(f"    {aid}")
    else:
        print(f"  agree on all {len(items)} artifacts")
    print()

    report = {
        "guard": manifest,
        "self_test": "passed" if ok else "failed",
        "attack_rows": len(rows),
        "artifacts_scanned": len(items),
        "summary": rust_summary,
        "equivalence": {
            "artifacts": len(items),
            "disagreements": len(mismatches),
            "disagreement_ids": mismatches[:50],
            "agrees": not mismatches,
        },
        "severity_counts": dict(Counter(
            f.severity for r in rust_results for f in r.findings
        )),
    }

    if args.write:
        RESULTS.parent.mkdir(parents=True, exist_ok=True)
        RESULTS.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {RESULTS.relative_to(ROOT)}")

    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())