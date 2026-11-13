"""Post-run safety review of a finished PHANTOM report.

The red-team evaluation measures the engine on synthetic evidence. This module is the
other half: it takes a report the forensic engine has already written for a real
investigation and applies the same three checks to it.

1. Injection scan. Every text field in the report (claims, evidence quotes, timeline
   events, narrative) is scanned for instructions aimed at an AI analyst.
2. Source independence. A finding's `verified_sources` is a list of source-key strings.
   The engine counts those strings, and the red-team work showed one process can
   appear under several of them. This check estimates how many distinct artifacts the
   keys describe and flags a CRITICAL finding that rests on fewer than three.
3. Cleared by wording. The engine's scorer returns CLEARED when the claim text contains
   a phrase such as "benign". This check flags every CLEARED finding whose claim carries
   such a phrase, so an analyst confirms the clearance from the evidence.

It is advisory. It reads a JSON file and writes flags; it never changes a verdict, and
it does not import or modify the forensic engine.

Limit, stated plainly: a report stores source keys and one evidence quote per finding,
not the full artifacts. The distinct-artifact figure is therefore an estimate (an upper
bound: two keys this module cannot relate are counted as two artifacts).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

from phantom_ai_safety.evidence_scanner.scanner import scan_artifact
from phantom_ai_safety.red_team.rows import BENIGN_INDICATORS

MIN_INDEPENDENT_ARTIFACTS = 3
MAX_TEXT_FIELDS = 20000          # safety valve for very large disk reports
MAX_FIELD_CHARS = 200000

FINDING_LISTS = (
    "critical_findings", "medium_findings", "low_findings",
    "cleared_findings", "refuted_hypotheses",
)

# engine:plugin or engine:plugin[pid]
_SOURCE_KEY = re.compile(r"^(?P<engine>[A-Za-z0-9_]+):(?P<plugin>[A-Za-z0-9_.\- ]+?)(?:\[(?P<pid>\d+)\])?$")

# Plugins that read the same underlying structure. Two keys from one group are one
# artifact seen twice, not two independent observations.
_PLUGIN_GROUPS = {
    "process_listing": {"pslist", "psscan", "pstree", "psxview", "linux_pslist", "linux_pstree"},
    "network_sockets": {"netscan", "netstat", "netscan_live", "linux_netstat", "sockstat"},
    "service_records": {"svcscan", "svclist", "svcdiff"},
    "memory_triage": {"triage", "strings_ioc", "yara_scan"},
}
_GROUP_OF = {plugin: group for group, plugins in _PLUGIN_GROUPS.items() for plugin in plugins}


def canonical_artifact(source_key: str) -> str:
    """Map one source key to the artifact it describes.

    Every per-PID key for one process is that one process. Plugins that walk the same
    structure share a group. Anything unrecognised stays as itself, which can only
    overstate independence, never understate it.
    """
    key = str(source_key).strip()
    match = _SOURCE_KEY.match(key)
    if not match:
        return key.lower()
    if match.group("pid"):
        return f"process:{match.group('pid')}"
    plugin = match.group("plugin").strip().lower()
    return _GROUP_OF.get(plugin, plugin)


def distinct_artifacts(source_keys: list) -> list[str]:
    return sorted({canonical_artifact(k) for k in source_keys or [] if str(k).strip()})


def _iter_strings(node: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    """Yield (json_path, text) for every string in the report."""
    if isinstance(node, str):
        if node.strip():
            yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _iter_strings(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _iter_strings(value, f"{path}[{index}]")


def _benign_phrase(claim: str) -> str | None:
    low = (claim or "").lower()
    for phrase in sorted(BENIGN_INDICATORS, key=len, reverse=True):
        if phrase in low:
            return phrase
    return None


def scan_report_text(report: Any) -> dict:
    """Run the injection scanner over every text field."""
    flagged, scanned, truncated = [], 0, False
    for path, text in _iter_strings(report):
        if scanned >= MAX_TEXT_FIELDS:
            truncated = True
            break
        scanned += 1
        result = scan_artifact(path, text[:MAX_FIELD_CHARS])
        if result.findings:
            flagged.append({
                "field": path,
                "highest_severity": result.highest_severity,
                "is_manipulated": result.is_manipulated,
                "signals": [
                    {"category": f.category, "severity": f.severity, "matched_text": f.matched_text}
                    for f in result.findings
                ],
            })
    return {"fields_scanned": scanned, "truncated": truncated, "flagged_fields": flagged}


def review_finding(finding: dict, bucket: str) -> dict:
    """Apply the source-independence and wording checks to one finding."""
    sources = [str(s) for s in (finding.get("verified_sources") or [])]
    artifacts = distinct_artifacts(sources)
    confidence = str(finding.get("confidence") or "").upper()
    claim = str(finding.get("claim") or "")
    flags = []

    if confidence == "CRITICAL" and len(artifacts) < MIN_INDEPENDENT_ARTIFACTS:
        flags.append({
            "check": "source_independence",
            "level": "high",
            "message": (
                f"Reported CRITICAL on {len(sources)} source key(s), which describe an estimated "
                f"{len(artifacts)} distinct artifact(s). At least {MIN_INDEPENDENT_ARTIFACTS} "
                "independent artifacts are expected before a finding is treated as confirmed."
            ),
        })

    phrase = _benign_phrase(claim)
    if confidence == "CLEARED" and phrase:
        corroborated = len(artifacts) >= MIN_INDEPENDENT_ARTIFACTS
        flags.append({
            "check": "cleared_by_wording",
            "level": "high" if corroborated else "review",
            "message": (
                f"CLEARED, and the claim text contains '{phrase}'. The engine's scorer clears a "
                "finding on that wording alone, so confirm the clearance from the evidence quote."
                + (f" Note: {len(artifacts)} distinct artifacts support the underlying "
                   "observation, which would otherwise have been reported as confirmed."
                   if corroborated else "")
            ),
        })

    return {
        "id": finding.get("id"),
        "bucket": bucket,
        "ioc": finding.get("ioc"),
        "confidence": confidence or None,
        "source_key_count": len(sources),
        "distinct_artifacts_estimate": len(artifacts),
        "artifacts": artifacts,
        "flags": flags,
    }


def review_report(report: dict) -> dict:
    """Review a parsed report. Returns a JSON-serialisable result."""
    findings = []
    if isinstance(report, dict):
        for bucket in FINDING_LISTS:
            for item in report.get(bucket) or []:
                if isinstance(item, dict):
                    findings.append(review_finding(item, bucket))

    injection = scan_report_text(report)
    finding_flags = [f for item in findings for f in item["flags"]]
    high = sum(1 for f in finding_flags if f["level"] == "high")
    high += sum(1 for f in injection["flagged_fields"] if f["is_manipulated"])
    review_level = sum(1 for f in finding_flags if f["level"] == "review")
    review_level += sum(1 for f in injection["flagged_fields"] if not f["is_manipulated"])

    metadata = report.get("metadata", {}) if isinstance(report, dict) else {}
    return {
        "tool": "phantom_ai_safety.review",
        "advisory": True,
        "target": metadata.get("target"),
        "report_timestamp": metadata.get("timestamp"),
        "summary": {
            "findings_reviewed": len(findings),
            "text_fields_scanned": injection["fields_scanned"],
            "high_flags": high,
            "review_flags": review_level,
            "status": "ATTENTION" if high else ("REVIEW" if review_level else "NO FLAGS"),
        },
        "findings": findings,
        "injection_scan": injection,
        "limits": [
            "Advisory only: no verdict in the original report is changed.",
            "Distinct-artifact counts are an upper-bound estimate from source keys; "
            "the report does not store the artifacts themselves.",
            "The injection scanner is rule-based; an unflagged field is not proof of safety.",
        ],
    }


def render_markdown(result: dict) -> str:
    s = result["summary"]
    lines = [
        "# PHANTOM safety review",
        "",
        f"- Target: `{result.get('target') or 'unknown'}`",
        f"- Status: **{s['status']}** ({s['high_flags']} high, {s['review_flags']} for review)",
        f"- Findings reviewed: {s['findings_reviewed']}; text fields scanned: {s['text_fields_scanned']}",
        "",
        "## Findings",
        "",
        "| id | confidence | source keys | distinct artifacts (est.) | flags |",
        "|---|---|---|---|---|",
    ]
    for item in result["findings"]:
        flags = "; ".join(f"{f['check']} ({f['level']})" for f in item["flags"]) or "none"
        lines.append(
            f"| {item['id']} | {item['confidence']} | {item['source_key_count']} | "
            f"{item['distinct_artifacts_estimate']} | {flags} |"
        )
    if not result["findings"]:
        lines.append("| (no finding lists in this report) | | | | |")
    lines += ["", "## Flag details", ""]
    details = [(item["id"], f) for item in result["findings"] for f in item["flags"]]
    for fid, flag in details:
        lines.append(f"- **{fid}** `{flag['check']}` ({flag['level']}): {flag['message']}")
    for field in result["injection_scan"]["flagged_fields"]:
        cats = ", ".join(sorted({sig["category"] for sig in field["signals"]}))
        lines.append(
            f"- **injection** `{field['field']}` ({field['highest_severity']}): {cats}"
        )
    if not details and not result["injection_scan"]["flagged_fields"]:
        lines.append("- None.")
    lines += ["", "## Limits", ""] + [f"- {limit}" for limit in result["limits"]] + [""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m phantom_ai_safety.review",
        description="Advisory safety review of a finished PHANTOM report (JSON).",
    )
    ap.add_argument("report", help="path to a PHANTOM report JSON")
    ap.add_argument("--out", help="write the review as JSON to this path")
    ap.add_argument("--md", help="write the review as Markdown to this path")
    ap.add_argument("--strict", action="store_true",
                    help="exit with status 1 when any high-level flag is raised")
    args = ap.parse_args(argv)

    path = Path(args.report)
    try:
        report = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except (OSError, ValueError) as exc:
        print(f"cannot read report: {exc}", file=sys.stderr)
        return 2

    result = review_report(report)
    markdown = render_markdown(result)
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.md:
        Path(args.md).write_text(markdown, encoding="utf-8")
    print(markdown)
    return 1 if (args.strict and result["summary"]["high_flags"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
