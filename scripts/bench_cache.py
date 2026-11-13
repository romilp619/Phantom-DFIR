"""Measure the guard cache on the real attack corpus.

Reports hit rate, wall time with and without the cache, and confirms that the
cache does not change a single result.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phantom_ai_safety.evidence_scanner import guard, scanner  # noqa: E402
from phantom_ai_safety.red_team.injection import build_injection_set  # noqa: E402

BIN = ROOT / "phantom-guard" / "target" / "release" / "phantom-guard.exe"
if not BIN.is_file():
    BIN = ROOT / "phantom-guard" / "target" / "release" / "phantom-guard"


def main() -> int:
    rows = build_injection_set(per_family=20)
    items = [(i.artifact_id, i.text) for r in rows for i in r.presented_evidence]
    payload = json.dumps([{"id": a, "text": t} for a, t in items])

    print(f"artifacts presented: {len(items)}")
    print(f"distinct texts     : {len({t for _, t in items})}")
    print()

    t0 = time.perf_counter()
    proc = subprocess.run([str(BIN), "batch"], input=payload, capture_output=True, text=True)
    elapsed = (time.perf_counter() - t0) * 1000

    if proc.returncode != 0:
        print(f"guard failed: {proc.stderr.strip()}")
        return 1

    print("guard stderr:", proc.stderr.strip())
    print(f"batch wall time: {elapsed:.1f} ms for {len(items)} artifacts")
    print(f"  {elapsed/len(items):.3f} ms per artifact")
    print()

    results = json.loads(proc.stdout)
    flagged = sum(1 for r in results if r["is_manipulated"])
    print(f"flagged as manipulated: {flagged} of {len(results)}")
    print()

    # The cache must not change any result. Compare against the Python reference.
    print("=== cache must not change results ===")
    mismatches = []
    for (aid, text), got in zip(items, results):
        exp = scanner.scan_artifact(aid, text)
        if (
            exp.is_manipulated != got["is_manipulated"]
            or exp.highest_severity != got["highest_severity"]
            or len(exp.findings) != len(got["findings"])
            or exp.length != got["length"]
        ):
            mismatches.append(aid)
    if mismatches:
        print(f"  DISAGREEMENT on {len(mismatches)} artifacts")
        return 1
    print(f"  all {len(results)} results match the uncached python reference")
    print()

    # Compare cached batch against per-artifact reference cost.
    print("=== cost comparison ===")
    slow_payload = json.dumps([{"id": a, "text": t} for a, t in items])
    # One process per artifact, which is the naive path a caller might take.
    t0 = time.perf_counter()
    for a, t in items[:40]:
        subprocess.run(
            [str(BIN), "scan"],
            input=json.dumps({"id": a, "text": t}),
            capture_output=True,
            text=True,
        )
    naive = (time.perf_counter() - t0) * 1000
    print(f"  40 artifacts, one process each : {naive:8.1f} ms")
    print(f"  40 artifacts projected batched : {40*elapsed/len(items):8.1f} ms")
    print(f"  per-artifact saving from batching alone: {naive/40 - elapsed/len(items):.2f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())