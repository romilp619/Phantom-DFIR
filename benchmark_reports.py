#!/usr/bin/env python3
"""
PHANTOM DFIR multi-case report benchmark.

This benchmark scores generated PHANTOM JSON/Markdown reports against the
artifact-level ground truth in benchmarks/ground_truth_cases.json. It is meant
for disk, memory, and PCAP challenge reports that already exist, so you can
validate a run without reprocessing a 10-minute evidence image.

Examples:
  python3 benchmark_reports.py --case nitroba_harassment_pcap \
      --report /home/romil/phantom_unified_pcap_nitroba.pcap_20260612_174103.md

  python3 benchmark_reports.py --case m57_jean_phishing \
      --reports-dir /home/romil --latest

  python3 benchmark_reports.py --all --reports-dir /home/romil --latest
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


ROOT = Path(__file__).resolve().parent
DEFAULT_GROUND_TRUTH = ROOT / "benchmarks" / "ground_truth_cases.json"


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def flatten_text(value: Any) -> str:
    """Turn JSON/Markdown content into searchable text."""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        parts: List[str] = []
        for k, v in value.items():
            parts.append(str(k))
            parts.append(flatten_text(v))
        return "\n".join(parts)
    if isinstance(value, list):
        return "\n".join(flatten_text(v) for v in value)
    return str(value)


def read_report(path: Path, include_sources: bool = True) -> str:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
            parts = [flatten_text(data)]
            if include_sources and isinstance(data, dict):
                for source in data.get("source_reports", [])[:8]:
                    source_path = Path(str(source)).expanduser()
                    if source_path.exists() and source_path.resolve() != path.resolve():
                        try:
                            parts.append(read_report(source_path, include_sources=False))
                        except Exception:
                            continue
            return "\n".join(parts)
        except Exception:
            return raw
    return raw


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower())


def alias_match(report_text: str, aliases: Iterable[str]) -> Tuple[bool, Optional[str]]:
    normalized = normalize(report_text)
    for alias in aliases:
        a = normalize(str(alias))
        if not a:
            continue
        if a in normalized:
            return True, str(alias)
    return False, None


def score_case(case: Dict[str, Any], report_text: str) -> Dict[str, Any]:
    expected = case.get("expected_findings", [])
    total_weight = sum(float(f.get("weight", 1)) for f in expected) or 1.0
    required = [f for f in expected if f.get("required", True)]
    required_weight = sum(float(f.get("weight", 1)) for f in required) or 1.0

    finding_results: List[Dict[str, Any]] = []
    matched_weight = 0.0
    matched_required_weight = 0.0
    required_misses = 0

    for finding in expected:
        matched, alias = alias_match(report_text, finding.get("aliases", []))
        weight = float(finding.get("weight", 1))
        if matched:
            matched_weight += weight
            if finding.get("required", True):
                matched_required_weight += weight
        elif finding.get("required", True):
            required_misses += 1
        finding_results.append({
            "id": finding.get("id"),
            "description": finding.get("description", ""),
            "required": bool(finding.get("required", True)),
            "weight": weight,
            "matched": matched,
            "matched_alias": alias,
        })

    verdict_match, verdict_alias = alias_match(
        report_text, case.get("expected_verdict_any", [])
    )

    forbidden_hits = []
    for phrase in case.get("forbidden", []):
        matched, alias = alias_match(report_text, [phrase])
        if matched:
            forbidden_hits.append(alias or phrase)

    coverage = matched_weight / total_weight
    required_coverage = matched_required_weight / required_weight
    penalty = min(0.25, 0.05 * len(forbidden_hits))
    adjusted = max(0.0, coverage - penalty)

    if adjusted >= 0.90 and required_coverage >= 0.90 and verdict_match and not forbidden_hits:
        status = "FULLY_REPRODUCED"
    elif adjusted >= 0.70 and required_coverage >= 0.60:
        status = "PARTIALLY_REPRODUCED"
    else:
        status = "NOT_REPRODUCED"

    return {
        "case_id": case.get("id"),
        "case_name": case.get("name"),
        "evidence_type": case.get("evidence_type"),
        "status": status,
        "coverage": round(coverage, 3),
        "required_coverage": round(required_coverage, 3),
        "adjusted_score": round(adjusted, 3),
        "verdict_match": verdict_match,
        "verdict_alias": verdict_alias,
        "required_misses": required_misses,
        "forbidden_hits": forbidden_hits,
        "findings": finding_results,
    }


def case_by_id(ground_truth: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    for case in ground_truth.get("cases", []):
        if case.get("id") == case_id:
            return case
    known = ", ".join(c.get("id", "?") for c in ground_truth.get("cases", []))
    raise SystemExit(f"[ERROR] Unknown case '{case_id}'. Known cases: {known}")


def discover_latest_report(case: Dict[str, Any], reports_dir: Path) -> Optional[Path]:
    """Find the newest likely report for a case by matching aliases/path hints."""
    candidates: List[Path] = []
    for pattern in ("phantom*.json", "phantom*.md", "*challenge_report.md"):
        candidates.extend(reports_dir.glob(pattern))
    candidates = [p for p in candidates if p.is_file()]
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    # Prefer a report whose filename hints at the case.
    hints = {
        "sysinternals_case": ["sysinternals", "susinternal"],
        "ali_hadi_web_server": ["ali", "web", "challenge1"],
        "cfreds_data_leakage": ["cfreds", "leakage", "informant"],
        "ali_hadi_encrypt_them_all": ["encrypt", "eta", "r2d2", "starwars"],
        "m57_jean_phishing": ["jean", "m57", "nps-2008-jean"],
        "nitroba_harassment_pcap": ["nitroba"],
        "base_admin_memory": ["base-admin", "memory"],
    }.get(case.get("id"), [])
    for p in candidates:
        name = p.name.lower()
        if any(h in name for h in hints):
            return p

    # Fallback: inspect a small number of reasonably sized reports for expected
    # aliases. Full forensic JSON can be very large; benchmark discovery should
    # not become another long-running analysis step.
    aliases: List[str] = []
    for finding in case.get("expected_findings", []):
        aliases.extend(finding.get("aliases", [])[:2])
    inspected = 0
    for p in candidates[:40]:
        try:
            if p.stat().st_size > 8 * 1024 * 1024:
                continue
        except OSError:
            continue
        try:
            text = read_report(p)
        except Exception:
            continue
        inspected += 1
        matches = sum(1 for alias in aliases if alias_match(text, [alias])[0])
        if matches >= 2:
            return p
        if inspected >= 12:
            break
    return None


def print_case_result(result: Dict[str, Any], report_path: Optional[Path] = None) -> None:
    print("=" * 72)
    print(f"{result['case_id']} — {result['case_name']}")
    if report_path:
        print(f"Report: {report_path}")
    print(f"Status: {result['status']}")
    print(f"Coverage: {result['coverage']:.1%}")
    print(f"Required coverage: {result['required_coverage']:.1%}")
    print(f"Adjusted score: {result['adjusted_score']:.1%}")
    print(f"Verdict matched: {result['verdict_match']} ({result.get('verdict_alias')})")
    if result["forbidden_hits"]:
        print("Forbidden hits:")
        for hit in result["forbidden_hits"]:
            print(f"  - {hit}")
    print("Findings:")
    for f in result["findings"]:
        mark = "✓" if f["matched"] else "✗"
        req = "required" if f["required"] else "optional"
        alias = f" via {f['matched_alias']}" if f["matched_alias"] else ""
        print(f"  {mark} {f['id']} [{req}, weight={f['weight']}]{alias}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Score PHANTOM reports against known challenge ground truth.")
    parser.add_argument("--ground-truth", default=str(DEFAULT_GROUND_TRUTH),
                        help="Ground truth JSON path")
    parser.add_argument("--case", help="Case id to score")
    parser.add_argument("--all", action="store_true", help="Score all cases")
    parser.add_argument("--report", action="append", default=[],
                        help="Report path. Can be repeated; all text is combined.")
    parser.add_argument("--reports-dir", default=os.path.expanduser("~"),
                        help="Directory used with --latest")
    parser.add_argument("--latest", action="store_true",
                        help="Find latest likely report for each requested case")
    parser.add_argument("--output", help="Write benchmark JSON result")
    args = parser.parse_args()

    gt_path = Path(args.ground_truth).expanduser()
    ground_truth = load_json(gt_path)

    if not args.all and not args.case:
        raise SystemExit("[ERROR] Use --case CASE_ID or --all")

    cases = ground_truth.get("cases", []) if args.all else [case_by_id(ground_truth, args.case)]
    reports_dir = Path(args.reports_dir).expanduser()
    all_results = []

    for case in cases:
        report_paths = [Path(p).expanduser() for p in args.report]
        selected_latest = None
        if args.latest:
            selected_latest = discover_latest_report(case, reports_dir)
            if selected_latest:
                report_paths = [selected_latest]
        if not report_paths:
            print(f"[WARN] No report supplied/found for {case.get('id')}; skipping")
            continue

        report_text_parts = []
        existing_paths = []
        for path in report_paths:
            if not path.exists():
                print(f"[WARN] Missing report: {path}")
                continue
            existing_paths.append(path)
            report_text_parts.append(read_report(path))
        if not report_text_parts:
            print(f"[WARN] No readable reports for {case.get('id')}; skipping")
            continue

        result = score_case(case, "\n".join(report_text_parts))
        result["reports"] = [str(p) for p in existing_paths]
        all_results.append(result)
        print_case_result(result, existing_paths[0] if len(existing_paths) == 1 else None)

    summary = {
        "timestamp": datetime.now().isoformat(),
        "ground_truth": str(gt_path),
        "cases_scored": len(all_results),
        "fully_reproduced": sum(1 for r in all_results if r["status"] == "FULLY_REPRODUCED"),
        "partially_reproduced": sum(1 for r in all_results if r["status"] == "PARTIALLY_REPRODUCED"),
        "not_reproduced": sum(1 for r in all_results if r["status"] == "NOT_REPRODUCED"),
        "average_adjusted_score": round(
            sum(r["adjusted_score"] for r in all_results) / max(len(all_results), 1), 3
        ),
        "results": all_results,
    }

    print("=" * 72)
    print("BENCHMARK SUMMARY")
    print(f"Cases scored: {summary['cases_scored']}")
    print(f"Fully reproduced: {summary['fully_reproduced']}")
    print(f"Partially reproduced: {summary['partially_reproduced']}")
    print(f"Not reproduced: {summary['not_reproduced']}")
    print(f"Average adjusted score: {summary['average_adjusted_score']:.1%}")

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Saved JSON: {out_path}")

    return 0 if summary["not_reproduced"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
