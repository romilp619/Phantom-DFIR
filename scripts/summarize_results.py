"""Print a compact per-family table from a results JSON.

Used to inspect which attack families actually succeed, rather than relying on the
aggregate. Run after `phantom_ai_safety.evaluation.baseline`.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
if PKG_ROOT not in sys.path:
    sys.path.insert(0, PKG_ROOT)


def fmt(value, width: int = 7) -> str:
    if value is None:
        return "n/a".rjust(width)
    return f"{value:.3f}".rjust(width)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="results JSON from the baseline or improved runner")
    ap.add_argument("--condition", default=None, help="condition name; default all")
    args = ap.parse_args()

    with open(args.path, encoding="utf-8") as fh:
        data = json.load(fh)

    conditions = data.get("conditions", {})
    names = [args.condition] if args.condition else list(conditions)

    print(f"file: {args.path}")
    env = data.get("environment", {})
    if env.get("source_digest_sha256"):
        print(f"source digest: {env['source_digest_sha256'][:16]}...")
    print(f"eval set: {json.dumps(data.get('eval_set', {}))}")

    for name in names:
        if name not in conditions:
            print(f"\n[skip] condition not present: {name}")
            continue
        block = conditions[name]
        overall = block.get("overall", {})
        print("\n" + "=" * 78)
        print(f"CONDITION: {name}")
        print("=" * 78)
        print(f"{'family':28s}{'n':>5}{'acc':>9}{'FCR':>9}{'ASR':>9}{'DMR':>9}{'XAR':>9}{'CR':>9}")
        print("-" * 78)
        for family, m in block.get("per_family", {}).items():
            print(
                f"{family:28s}{m.get('n', 0):>5}"
                f"{fmt(m.get('accuracy'))}{fmt(m.get('false_confirm_rate'))}"
                f"{fmt(m.get('attack_success_rate'))}{fmt(m.get('dangerous_miss_rate'))}"
                f"{fmt(m.get('correct_abstention_rate'))}{fmt(m.get('capability_retention'))}"
            )
        print("-" * 78)
        print(
            f"{'OVERALL':28s}{overall.get('n', 0):>5}"
            f"{fmt(overall.get('accuracy'))}{fmt(overall.get('false_confirm_rate'))}"
            f"{fmt(overall.get('attack_success_rate'))}{fmt(overall.get('dangerous_miss_rate'))}"
            f"{fmt(overall.get('correct_abstention_rate'))}{fmt(overall.get('capability_retention'))}"
        )

    if "invariance" in data:
        print("\nINVARIANCE")
        for strategy, info in data["invariance"].items():
            print(f"  {strategy:18s} changed_rows={info['changed_rows']}")
    print("\nlegend: FCR false-confirm  ASR attack-success  DMR dangerous-miss  "
          "XAR correct-abstention  CR capability-retention")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())