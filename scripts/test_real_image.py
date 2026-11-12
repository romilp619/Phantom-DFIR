"""Integration test: real Volatility output through the scanner and guard.

The synthetic red-team rows test the reasoning layer. This tests the thing they
cannot: real plugin output, with real formatting, real hex dumps, real wide tables,
real non-ASCII, real noise. If the scanner false-positives on a clean image it is
worse than useless, because an analyst triaging a clean host would learn to ignore it.

Runs the Python scanner and the Rust guard over every captured plugin output file and
reports:
  - whether anything false-positives on real clean evidence
  - whether the two implementations still agree
  - scan cost on real-sized artifacts

Run:  python scripts/test_real_image.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phantom_ai_safety.evidence_scanner import guard, scanner  # noqa: E402

OUT_DIR = ROOT / "test-images" / "plugin-output"


def main() -> int:
    if not OUT_DIR.is_dir():
        print(f"no plugin output at {OUT_DIR}")
        print("run scripts/run_real_image_plugins.sh first")
        return 2

    files = sorted(p for p in OUT_DIR.glob("*.txt") if p.stat().st_size > 0)
    if not files:
        print("no non-empty plugin outputs found")
        return 2

    print(f"=== scanning {len(files)} real Volatility outputs ===")
    print()

    total_bytes = 0
    flagged_total = 0
    disagreements = []
    rows = []

    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        total_bytes += len(text)

        t0 = time.perf_counter()
        py = scanner.scan_artifact(path.stem, text)
        py_ms = (time.perf_counter() - t0) * 1000

        if guard.available():
            t0 = time.perf_counter()
            rs = guard.scan_artifact(path.stem, text)
            rs_ms = (time.perf_counter() - t0) * 1000
        else:
            rs = None
            rs_ms = 0.0

        cats = [f.category for f in py.findings]
        if py.is_manipulated:
            flagged_total += 1

        rows.append({
            "plugin": path.stem,
            "chars": len(text),
            "py_ms": py_ms,
            "rs_ms": rs_ms,
            "findings": len(py.findings),
            "categories": cats,
            "manipulated": py.is_manipulated,
        })

        if rs is not None:
            if py.is_manipulated != rs.is_manipulated:
                disagreements.append(f"{path.stem}: is_manipulated {py.is_manipulated} != {rs.is_manipulated}")
            if py.highest_severity != rs.highest_severity:
                disagreements.append(f"{path.stem}: severity {py.highest_severity} != {rs.highest_severity}")

    hdr = f"{'plugin':<24} {'chars':>8} {'findings':>9} {'severity':>10} {'py ms':>8} {'rust ms':>8}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(
            f"{r['plugin']:<24} {r['chars']:>8,} {r['findings']:>9} "
            f"{'FLAGGED' if r['manipulated'] else 'clean':>10} "
            f"{r['py_ms']:>8.1f} {r['rs_ms']:>8.1f}"
        )
    print()

    # Detail any finding, so a false positive on clean evidence is impossible to miss.
    if flagged_total:
        print("=== FINDINGS ON REAL EVIDENCE (inspect for false positives) ===")
        for r in rows:
            if r["manipulated"]:
                print(f"  {r['plugin']}: {r['categories']}")
        print()

    print(f"real evidence scanned : {total_bytes:,} chars across {len(files)} plugin outputs")
    print(f"flagged as manipulated: {flagged_total} of {len(files)}")
    if guard.available():
        print(f"guard disagreements   : {len(disagreements)}")
        for d in disagreements:
            print(f"  {d}")
    else:
        print("guard not built; skipped cross-check")
    print()

    # A clean host image must not look manipulated. This is the headline result.
    if flagged_total == 0:
        print("RESULT: no false positives on a real clean-host memory image")
    else:
        print(f"RESULT: {flagged_total} plugin output(s) flagged -- review each one")

    return 0 if not disagreements else 1


if __name__ == "__main__":
    raise SystemExit(main())