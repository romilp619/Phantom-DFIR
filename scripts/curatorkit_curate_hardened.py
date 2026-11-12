"""CuratorKIT curation, hardened against the toolkit's three silent failures.

Replaces `curatorkit_curate.py`, which discovered the defects but did not defend against
them. This runner validates the configuration before the run and verifies the outcome
after, so a bad run fails loudly instead of reporting a clean pass rate over corrupted
data.

Fixes carried in by `phantom_ai_safety.curation.guards`:

  1. format      - an invalid container name ('jsonl') raises instead of rejecting every row
  2. strip_html  - disabled by default, because this corpus' angle-bracket markers ARE the
                   evidence anchors, and the upstream default deletes all of them
  3. injection   - a non-zero injection_rate without injection_types raises instead of
                   silently doing nothing

Usage:
    python scripts/curatorkit_curate_hardened.py --train data/train.jsonl \
        --out results/curatorkit_report.json

Exit codes: 0 success, 1 configuration/verification failure, 2 toolkit unavailable.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
if PKG_ROOT not in sys.path:
    sys.path.insert(0, PKG_ROOT)

from phantom_ai_safety.curation.guards import (  # noqa: E402
    CurationConfigError,
    cross_check_formats,
    safe_clean_transforms,
    validate_config,
    verify_run,
)


def project_chat_to_alpaca(src: str, dst: str, limit: int | None = None) -> dict:
    """Project chat rows to alpaca, carrying id and family through for provenance.

    The projection is audited and returned rather than assumed. A silent field drop is
    the same class of defect this project audits elsewhere.
    """
    stats = {"rows_in": 0, "projected": 0, "missing_system": 0, "missing_user": 0,
             "missing_assistant": 0, "ids_preserved": 0}
    with open(src, "r", encoding="utf-8") as fh_in, \
         open(dst, "w", encoding="utf-8") as fh_out:
        for i, line in enumerate(fh_in):
            if limit is not None and i >= limit:
                break
            stats["rows_in"] += 1
            rec = json.loads(line)
            by = {}
            for m in rec.get("messages") or []:
                by[m.get("role")] = m.get("content", "")
            for role, key in (("system", "missing_system"),
                              ("user", "missing_user"),
                              ("assistant", "missing_assistant")):
                if not by.get(role):
                    stats[key] += 1
            if rec.get("id"):
                stats["ids_preserved"] += 1
            fh_out.write(json.dumps({
                "instruction": by.get("system", "").strip(),
                "input": by.get("user", "").strip(),
                "output": by.get("assistant", "").strip(),
                "id": rec.get("id"),
                "family": rec.get("family"),
            }) + "\n")
            stats["projected"] += 1
    return stats


def run_curation(dataset: str, format_name: str, output_dir: str, name: str,
                 injection_rate: float = 0.0, injection_types=None):
    """Run one curated pass with the guarded configuration."""
    from curatorkit import Curator, CuratorConfig

    fields = (getattr(CuratorConfig, "model_fields", None)
              or getattr(CuratorConfig, "__dataclass_fields__", None) or {})
    allowed = set(fields)

    wanted = dict(
        dataset=dataset,
        format=format_name,
        output_dir=output_dir,
        name=name,
        injection_rate=injection_rate,
        clean_transforms=safe_clean_transforms(keep_markers=True),
        write_hf_readme=False,
    )
    if injection_types:
        wanted["injection_types"] = list(injection_types)

    kwargs = {k: v for k, v in wanted.items() if k in allowed}
    t0 = time.time()
    res = Curator(CuratorConfig(**kwargs)).run()
    return res, time.time() - t0


def main() -> int:
    ap = argparse.ArgumentParser(description="Hardened CuratorKIT curation")
    ap.add_argument("--train", default="data/train.jsonl")
    ap.add_argument("--format", default="alpaca")
    ap.add_argument("--out", default="results/curatorkit_report.json")
    ap.add_argument("--workdir", default="/tmp/phantom_curation")
    ap.add_argument("--injection-rate", type=float, default=0.0)
    ap.add_argument("--injection-types", nargs="*", default=None)
    ap.add_argument("--sample", type=int, default=None,
                    help="curate only the first N rows (for a fast smoke run)")
    args = ap.parse_args()

    try:
        import curatorkit  # noqa: F401
    except Exception as exc:
        print(f"curatorkit unavailable: {exc}", file=sys.stderr)
        return 2

    os.makedirs(args.workdir, exist_ok=True)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    drift = cross_check_formats()
    if drift.get("available") and not drift["in_sync"]:
        print(f"WARNING: format enum drifted from installed toolkit: {drift}")

    # ---- validate BEFORE running (defects 1-3)
    try:
        guard = validate_config(
            format=args.format,
            injection_rate=args.injection_rate,
            injection_types=args.injection_types,
            clean_transforms=safe_clean_transforms(keep_markers=True),
            keep_markers=True,
        )
    except CurationConfigError as exc:
        print(f"CONFIG REJECTED: {exc}", file=sys.stderr)
        return 1
    print(f"config guard: ok  checked={guard.checked}")

    # ---- project
    projected = os.path.join(args.workdir, "phantom_alpaca.jsonl")
    pstats = project_chat_to_alpaca(args.train, projected, limit=args.sample)
    print(f"projection: {json.dumps(pstats)}")

    # ---- run
    try:
        res, elapsed = run_curation(
            projected, args.format, os.path.join(args.workdir, "out"),
            "phantom_train", args.injection_rate, args.injection_types,
        )
    except Exception as exc:
        print(f"CURATION FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    passed = list(res.passed or [])
    rejected = list(res.rejected or [])

    # ---- verify AFTER running (defects 1 and 2, outcome side)
    try:
        post = verify_run(passed, rejected, expected_markers=True)
    except CurationConfigError as exc:
        print(f"POST-RUN VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 1

    reasons: dict[str, int] = {}
    for r in rejected:
        key = str(getattr(r, "reason", None) or getattr(r, "stage", None)
                  or type(r).__name__)[:60]
        reasons[key] = reasons.get(key, 0) + 1

    report = {
        "toolkit": "curatorkit",
        "toolkit_version": getattr(__import__("curatorkit"), "__version__", "unknown"),
        "hardened_by": "phantom_ai_safety.curation.guards",
        "input": args.train,
        "format": args.format,
        "projection": pstats,
        "config_guard": guard.to_dict(),
        "post_run_guard": post.to_dict(),
        "rows_curated": len(passed) + len(rejected),
        "passed": len(passed),
        "rejected": len(rejected),
        "pass_rate": round(len(passed) / (len(passed) + len(rejected)), 4)
        if (len(passed) + len(rejected)) else None,
        "stage_counts": res.stage_counts,
        "rejection_reasons": reasons,
        "wall_clock_seconds": round(elapsed, 2),
        "injection_rate": args.injection_rate,
        "evidence_markers_preserved": True,
        "notes": [
            "strip_html disabled so angle-bracket evidence markers survive cleaning",
            "format validated against DataFormat; 'jsonl' would reject 100% of rows silently",
            "a non-zero injection_rate without injection_types is refused",
        ],
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    print(f"curated {report['rows_curated']} rows -> {len(passed)} passed, "
          f"{len(rejected)} rejected in {elapsed:.2f}s")
    print(f"post-run guard: ok  checked={post.checked}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())