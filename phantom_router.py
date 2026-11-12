#!/usr/bin/env python3
"""
PHANTOM DFIR - Thin Evidence Router

Additive orchestration layer only. Existing entry points remain unchanged:
  python3 main.py ...
  python3 disk_correlator.py ...
  python3 mcpserver/mcp_server.py ...

This router detects the evidence type, runs the existing validated tool, reads
the JSON reports that tool already produced, optionally asks the configured LLM
provider for a unified analysis, and writes an additional unified report.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


ROOT = Path(__file__).resolve().parent
MEMORY_EXTENSIONS = {".mem", ".raw", ".vmem"}
DISK_EXTENSIONS = {".e01", ".dd", ".img"}
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="PHANTOM DFIR - unified evidence router",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 phantom_router.py memory.mem --self-correct
  python3 phantom_router.py image.E01 --deep
  python3 phantom_router.py network.pcap --deep
  python3 phantom_router.py image.dd --output-dir /cases/out --no-timeline

Existing tools remain available and unchanged:
  python3 main.py -f memory.mem --self-correct
  python3 disk_correlator.py -d image.E01 --deep
        """,
    )
    p.add_argument("evidence", help="Evidence file: memory, disk image, or PCAP")
    p.add_argument("-o", "--output-dir", default=os.path.expanduser("~"),
                   help="Directory for reports (default: ~/)")
    p.add_argument("--type", choices=["auto", "memory", "disk", "pcap"], default="auto",
                   help="Override evidence type detection")

    # Existing main.py-compatible reasoning options. These are passed only to
    # main.py for memory evidence, and also used by the router's unified LLM step.
    p.add_argument("--model", default=None, help="LLM model name")
    p.add_argument("--ollama-url", default=None, help="Ollama base URL")
    p.add_argument("--provider", choices=["ollama", "claude", "openai", "groq"],
                   default=None, help="LLM provider for unified reasoning")
    p.add_argument("--api-key", default=None, help="API key for cloud LLM providers")
    p.add_argument("--no-llm", action="store_true",
                   help="Skip router unified LLM analysis and pass through to main.py")
    p.add_argument("--self-correct", action="store_true",
                   help="Pass through to main.py for memory evidence")
    p.add_argument("--max-iterations", type=int, default=3,
                   help="Pass through to main.py self-correction")
    p.add_argument("--threshold", type=int, default=50,
                   help="Pass through to main.py self-correction")
    p.add_argument("--vol3", default=None, help="Pass through to main.py")
    p.add_argument("--vol2", default=None, help="Pass through to main.py")

    # Existing disk_correlator.py-compatible options.
    p.add_argument("--deep", dest="deep", action="store_true", default=True,
                   help="Run disk_correlator.py --deep for disk/PCAP evidence (default)")
    p.add_argument("--no-deep", dest="deep", action="store_false",
                   help="Do not pass --deep to disk_correlator.py")
    p.add_argument("--no-timeline", action="store_true",
                   help="Pass through to disk_correlator.py")

    p.add_argument("--timeout", type=int, default=0,
                   help="Optional child process timeout in seconds (0 = no timeout)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print selected command without running it")
    p.add_argument("--no-evidence-self-correct", action="store_true",
                   help="Disable router-level gap checks/reruns for disk and PCAP evidence")
    p.add_argument("--gap-confidence", type=float, default=0.85,
                   help="Target confidence for router evidence gap controller (default: 0.85)")
    return p.parse_args()


def read_magic(path: Path, size: int = 8) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(size)
    except Exception:
        return b""


def detect_evidence_type(path: Path, override: str = "auto") -> str:
    if override != "auto":
        return override
    ext = path.suffix.lower()
    magic = read_magic(path, 8)
    if ext in PCAP_EXTENSIONS or magic[:4] in PCAP_MAGIC:
        return "pcap"
    if ext in MEMORY_EXTENSIONS:
        return "memory"
    if ext in DISK_EXTENSIONS:
        return "disk"
    # E01/EWF usually starts with EVF. Keep this as a conservative magic hint.
    if magic.startswith(b"EVF"):
        return "disk"
    raise SystemExit(
        f"[ERROR] Unsupported evidence type for {path}. "
        "Use --type memory|disk|pcap to override."
    )


def build_command(args: argparse.Namespace, evidence_type: str) -> List[str]:
    evidence = str(Path(args.evidence).expanduser())
    output_dir = str(Path(args.output_dir).expanduser())
    py = sys.executable or "python3"

    if evidence_type == "memory":
        cmd = [py, str(ROOT / "main.py"), "-f", evidence, "--output-dir", output_dir]
        if args.model:
            cmd += ["--model", args.model]
        if args.ollama_url:
            cmd += ["--ollama-url", args.ollama_url]
        if args.provider:
            cmd += ["--provider", args.provider]
        if args.api_key:
            cmd += ["--api-key", args.api_key]
        if args.no_llm:
            cmd.append("--no-llm")
        if args.vol3:
            cmd += ["--vol3", args.vol3]
        if args.vol2:
            cmd += ["--vol2", args.vol2]
        if args.self_correct:
            cmd += [
                "--self-correct",
                "--max-iterations", str(args.max_iterations),
                "--threshold", str(args.threshold),
            ]
        return cmd

    if evidence_type in {"disk", "pcap"}:
        cmd = [py, str(ROOT / "disk_correlator.py"), "-d", evidence, "-o", output_dir]
        if args.deep:
            cmd.append("--deep")
        if args.no_timeline:
            cmd.append("--no-timeline")
        return cmd

    raise SystemExit(f"[ERROR] Unknown evidence type: {evidence_type}")


def stream_command(cmd: List[str], cwd: Path, timeout: int = 0) -> Tuple[int, str]:
    started = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        bufsize=1,
    )
    lines: List[str] = []
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
            lines.append(line)
            if timeout and (time.time() - started) > timeout:
                proc.kill()
                lines.append(f"\n[PHANTOM_ROUTER] Timeout after {timeout}s\n")
                return 124, "".join(lines)
        return proc.wait(), "".join(lines)
    finally:
        try:
            proc.stdout.close() if proc.stdout else None
        except Exception:
            pass


def extract_report_paths(stdout: str) -> List[Path]:
    paths: List[Path] = []
    for line in stdout.splitlines():
        # Handles:
        #   JSON: /path/report.json
        #   Deep forensic JSON: /path/report_forensic_exam.json
        #   MD: /path/report.md
        for match in re.finditer(r"(?i)(?:JSON|MD)\s*:\s*(/.+?\.(?:json|md))\b", line):
            paths.append(Path(match.group(1).strip()))
    return unique_existing(paths)


def scan_fresh_reports(output_dir: Path, started_at: float) -> List[Path]:
    paths: List[Path] = []
    try:
        for pattern in ("phantom*.json", "phantom*.md", "*_forensic_exam.json", "*_challenge_report.md"):
            for p in output_dir.glob(pattern):
                try:
                    if p.stat().st_mtime >= started_at - 2:
                        paths.append(p)
                except OSError:
                    continue
    except Exception:
        pass
    return unique_existing(paths)


def unique_existing(paths: Iterable[Path]) -> List[Path]:
    seen = set()
    result = []
    for p in paths:
        try:
            resolved = p.expanduser().resolve()
        except Exception:
            resolved = p.expanduser()
        if resolved in seen or not resolved.exists():
            continue
        seen.add(resolved)
        result.append(resolved)
    return result


def load_json_reports(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    loaded = []
    for p in paths:
        if p.suffix.lower() != ".json":
            continue
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                loaded.append({"path": str(p), "data": json.load(f)})
        except Exception as e:
            loaded.append({"path": str(p), "error": str(e)})
    return loaded


def _count_key_hits(value: Any, key_patterns: Iterable[str]) -> int:
    patterns = [re.compile(p, re.I) for p in key_patterns]
    count = 0
    if isinstance(value, dict):
        for key, child in value.items():
            if any(p.search(str(key)) for p in patterns):
                if isinstance(child, list):
                    count += len(child)
                elif isinstance(child, dict):
                    count += len(child)
                elif child not in ("", None, 0, False):
                    count += 1
            count += _count_key_hits(child, key_patterns)
    elif isinstance(value, list):
        for child in value:
            count += _count_key_hits(child, key_patterns)
    return count


def _gap_text_blob(value: Any, limit: int = 250000) -> str:
    try:
        text = json.dumps(value, default=str)
    except Exception:
        text = str(value)
    return text[:limit].lower()


def _gap_controller_confidence(
    evidence_type: str,
    reports: List[Dict[str, Any]],
    stdout: str,
) -> Tuple[float, List[Dict[str, Any]]]:
    """Conservative coverage check for non-memory evidence routes."""
    gaps: List[Dict[str, Any]] = []
    payload = {"reports": reports, "stdout_tail": stdout[-20000:]}
    blob = _gap_text_blob(payload)

    def add_gap(name: str, severity: str, detail: str, action: str) -> None:
        gaps.append({
            "gap": name,
            "severity": severity,
            "detail": detail,
            "recommended_action": action,
        })

    if not reports:
        add_gap(
            "missing_structured_reports",
            "high",
            "No JSON reports were discovered after the child analyzer finished.",
            "rerun_child_analyzer",
        )
    if "verdict" not in blob and "reasoning" not in blob:
        add_gap(
            "missing_reasoning_verdict",
            "medium",
            "No verdict or reasoning object was visible in generated reports.",
            "rerun_with_deep_analysis",
        )

    if evidence_type == "disk":
        timeline_hits = _count_key_hits(payload, [r"timeline", r"events"])
        registry_hits = _count_key_hits(payload, [r"registry", r"hive", r"userassist", r"amcache", r"bam"])
        execution_hits = _count_key_hits(payload, [r"prefetch", r"execution", r"program", r"service"])
        user_hits = _count_key_hits(payload, [r"account", r"user", r"sid"])

        if timeline_hits < 3:
            add_gap(
                "disk_timeline_sparse",
                "medium",
                "Few or no timeline events were recovered from disk artifacts.",
                "rerun_with_timeline_enabled",
            )
        if registry_hits < 2:
            add_gap(
                "registry_artifacts_sparse",
                "medium",
                "Registry and user-execution artifact coverage appears sparse.",
                "rerun_with_deep_analysis",
            )
        if execution_hits < 2:
            add_gap(
                "execution_artifacts_sparse",
                "medium",
                "Execution evidence such as Prefetch/UserAssist/Amcache/BAM/services appears sparse.",
                "rerun_with_deep_analysis",
            )
        if user_hits < 1:
            add_gap(
                "user_attribution_sparse",
                "low",
                "No clear user/account attribution artifacts were visible.",
                "rerun_with_deep_analysis",
            )

    elif evidence_type == "pcap":
        flow_hits = _count_key_hits(payload, [r"flow", r"conversation", r"http", r"dns", r"tls"])
        identity_hits = _count_key_hits(payload, [r"identity", r"webmail", r"account", r"participant"])
        communication_hits = _count_key_hits(payload, [r"communication", r"post", r"message", r"sender", r"recipient"])
        classification_hits = _count_key_hits(payload, [r"classification", r"attribution", r"verdict"])

        if flow_hits < 3:
            add_gap(
                "network_flow_sparse",
                "high",
                "Network flow/protocol coverage is sparse for a PCAP input.",
                "rerun_with_deep_analysis",
            )
        if identity_hits < 1:
            add_gap(
                "identity_attribution_missing",
                "medium",
                "No identity/webmail/account attribution evidence was visible.",
                "rerun_pcap_attribution",
            )
        if communication_hits < 1:
            add_gap(
                "communication_context_missing",
                "medium",
                "No message/POST/sender/recipient communication context was visible.",
                "rerun_pcap_attribution",
            )
        if classification_hits < 1:
            add_gap(
                "network_classification_missing",
                "medium",
                "No network case classification or attribution verdict was visible.",
                "rerun_with_deep_analysis",
            )

    penalty = 0.0
    for item in gaps:
        severity = item.get("severity")
        penalty += 0.28 if severity == "high" else 0.16 if severity == "medium" else 0.08
    return max(0.0, min(1.0, 1.0 - penalty)), gaps


def _gap_controller_next_command(
    command: List[str],
    evidence_type: str,
    gaps: List[Dict[str, Any]],
) -> Tuple[List[str], List[str]]:
    next_cmd = list(command)
    actions: List[str] = []
    wanted = {item.get("recommended_action", "") for item in gaps}

    if evidence_type in {"disk", "pcap"}:
        if "rerun_with_deep_analysis" in wanted or "rerun_pcap_attribution" in wanted:
            if "--no-deep" in next_cmd:
                next_cmd = [item for item in next_cmd if item != "--no-deep"]
                actions.append("removed --no-deep")
            if "--deep" not in next_cmd:
                next_cmd.append("--deep")
                actions.append("enabled --deep analysis")
        if "rerun_with_timeline_enabled" in wanted and "--no-timeline" in next_cmd:
            next_cmd = [item for item in next_cmd if item != "--no-timeline"]
            actions.append("enabled timeline generation")

    if next_cmd == command:
        actions.append("no safer additional command change available; child engine already ran requested modules")
    return next_cmd, actions


def evidence_gap_controller(
    evidence_type: str,
    command: List[str],
    output_dir: Path,
    initial_started: float,
    initial_returncode: int,
    initial_stdout: str,
    args: argparse.Namespace,
) -> Tuple[int, str, List[Path], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Bounded router self-correction for disk and PCAP evidence."""
    trace: List[Dict[str, Any]] = []
    stdout = initial_stdout
    returncode = initial_returncode
    report_paths = unique_existing(
        extract_report_paths(stdout) + scan_fresh_reports(output_dir, initial_started)
    )
    json_reports = load_json_reports(report_paths)

    if evidence_type == "memory" or args.no_evidence_self_correct:
        return returncode, stdout, report_paths, json_reports, trace

    current_command = list(command)
    max_iterations = max(1, min(int(args.max_iterations or 1), 3))
    target = max(0.0, min(float(args.gap_confidence), 1.0))

    for iteration in range(1, max_iterations + 1):
        confidence, gaps = _gap_controller_confidence(evidence_type, json_reports, stdout)
        next_command, actions = _gap_controller_next_command(current_command, evidence_type, gaps)
        record = {
            "iteration": iteration,
            "timestamp": datetime.now().isoformat(),
            "evidence_type": evidence_type,
            "confidence": round(confidence, 3),
            "target_confidence": target,
            "gaps": gaps,
            "actions": actions,
            "command": current_command,
        }
        trace.append(record)

        print("=" * 64)
        print("PHANTOM ROUTER - Evidence Gap Controller")
        print("=" * 64)
        print(f"Iteration      : {iteration}/{max_iterations}")
        print(f"Evidence type  : {evidence_type}")
        print(f"Confidence     : {confidence:.2f} / target {target:.2f}")
        print(f"Gaps detected  : {len(gaps)}")
        for item in gaps[:8]:
            print(f"  - [{item.get('severity')}] {item.get('gap')}: {item.get('detail')}")
        for action in actions:
            print(f"Action         : {action}")

        if confidence >= target or not gaps:
            record["decision"] = "complete"
            break
        if next_command == current_command:
            record["decision"] = "stopped_no_new_command"
            break
        if iteration >= max_iterations:
            record["decision"] = "stopped_max_iterations"
            break

        record["decision"] = "rerun"
        current_command = next_command
        started = time.time()
        returncode, stdout = stream_command(current_command, ROOT, timeout=args.timeout)
        report_paths = unique_existing(
            extract_report_paths(stdout) + scan_fresh_reports(output_dir, started)
        )
        json_reports = load_json_reports(report_paths)

    return returncode, stdout, report_paths, json_reports, trace


def compact_value(value: Any, depth: int = 0, max_list: int = 6) -> Any:
    if depth > 4:
        return "<truncated>"
    if isinstance(value, dict):
        compact = {}
        priority = [
            "verdict", "suspicion_score", "summary", "metadata", "reasoning",
            "attack_narrative", "critical_findings", "medium_findings",
            "network_forensics", "malware_intelligence", "challenge_analysis",
            "pcap_attack_classification", "network_attack_timeline",
        ]
        keys = priority + [k for k in value.keys() if k not in priority]
        for key in keys[:40]:
            if key in value:
                compact[key] = compact_value(value[key], depth + 1, max_list)
        return compact
    if isinstance(value, list):
        return [compact_value(v, depth + 1, max_list) for v in value[:max_list]]
    if isinstance(value, str):
        return value[:700] + ("..." if len(value) > 700 else "")
    return value


def summarize_reports(json_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    summaries = []
    for report in json_reports:
        data = report.get("data")
        if not isinstance(data, dict):
            summaries.append(report)
            continue
        summaries.append({
            "path": report.get("path"),
            "verdict": data.get("verdict") or (data.get("reasoning") or {}).get("verdict"),
            "suspicion_score": data.get("suspicion_score"),
            "summary": compact_value(data.get("summary", {})),
            "metadata": compact_value(data.get("metadata", {})),
            "attack_narrative": compact_value(data.get("attack_narrative", "")),
            "reasoning": compact_value(data.get("reasoning", {})),
            "network_forensics": compact_value(data.get("network_forensics", {})),
            "challenge_analysis": compact_value(data.get("challenge_analysis", {})),
            "malware_intelligence": compact_value(data.get("malware_intelligence", {})),
        })
    return {"reports": summaries}


def configure_llm(args: argparse.Namespace) -> None:
    try:
        import config
    except Exception:
        return
    if args.model:
        config.OLLAMA_MODEL = args.model
    if args.ollama_url:
        config.OLLAMA_BASE_URL = args.ollama_url
    if args.provider:
        config.LLM_PROVIDER = args.provider
    if args.api_key:
        config.LLM_API_KEY = args.api_key


def llm_invoke_text(prompt: str, args: argparse.Namespace) -> Tuple[str, str]:
    if args.no_llm:
        return "skipped", "Router unified LLM analysis skipped with --no-llm."
    configure_llm(args)
    try:
        from tools.llm_provider import create_llm
        llm = create_llm(temperature=0.1, timeout=180)
        response = llm.invoke(prompt)
        if hasattr(response, "content"):
            return "ok", str(response.content)
        return "ok", str(response)
    except Exception as e:
        return "error", f"Unified LLM analysis unavailable: {e}"


def make_unified_prompt(evidence_type: str, evidence_path: Path, summary: Dict[str, Any]) -> str:
    payload = json.dumps(summary, indent=2, default=str)
    if len(payload) > 18000:
        payload = payload[:18000] + "\n...TRUNCATED: compact evidence summary exceeded router LLM budget..."
    return f"""You are PHANTOM DFIR's unified analyst layer.

Evidence type: {evidence_type}
Evidence path: {evidence_path}

The extraction/scanning tools have already produced these JSON findings.
Do not invent unsupported evidence. Preserve uncertainty. Produce a concise
unified forensic report with:

1. Final analyst verdict
2. Key evidence
3. Attack type or benign explanation
4. Timeline summary if available
5. Malware/network/memory/disk highlights as applicable
6. Gaps and recommended next steps

Findings JSON summary:
{payload}
"""


def write_unified_reports(
    output_dir: Path,
    evidence_path: Path,
    evidence_type: str,
    command: List[str],
    returncode: int,
    report_paths: List[Path],
    json_reports: List[Dict[str, Any]],
    llm_status: str,
    llm_text: str,
    stdout_tail: str,
    gap_trace: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Path, Path]:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", evidence_path.name)[:80]
    json_path = output_dir / f"phantom_unified_{evidence_type}_{stem}_{ts}.json"
    md_path = output_dir / f"phantom_unified_{evidence_type}_{stem}_{ts}.md"

    unified = {
        "metadata": {
            "tool": "PHANTOM DFIR Unified Router",
            "timestamp": datetime.now().isoformat(),
            "evidence_path": str(evidence_path),
            "evidence_type": evidence_type,
            "command": command,
            "returncode": returncode,
        },
        "source_reports": [str(p) for p in report_paths],
        "json_findings_summary": summarize_reports(json_reports),
        "llm_status": llm_status,
        "unified_analysis": llm_text,
        "evidence_gap_controller": gap_trace or [],
        "stdout_tail": stdout_tail[-12000:],
    }
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(unified, f, indent=2, default=str)

    md = [
        "# PHANTOM DFIR - Unified Router Report",
        "",
        f"**Evidence**: `{evidence_path}`",
        f"**Evidence type**: `{evidence_type}`",
        f"**Child return code**: `{returncode}`",
        f"**Timestamp**: {datetime.now().isoformat()}",
        "",
        "## Routed Command",
        "",
        "```bash",
        " ".join(command),
        "```",
        "",
        "## Source Reports",
        "",
    ]
    if report_paths:
        md.extend(f"- `{p}`" for p in report_paths)
    else:
        md.append("- No source reports discovered.")

    md += [
        "",
        "## Unified Analysis",
        "",
        f"**LLM status**: `{llm_status}`",
        "",
        llm_text.strip() or "No unified analysis text generated.",
        "",
        "## Evidence Gap Controller",
        "",
    ]
    if gap_trace:
        final_gap = gap_trace[-1]
        md.extend([
            f"**Iterations**: {len(gap_trace)}",
            f"**Final confidence**: `{final_gap.get('confidence')}`",
            f"**Target confidence**: `{final_gap.get('target_confidence')}`",
            f"**Decision**: `{final_gap.get('decision', 'recorded')}`",
            "",
        ])
        if final_gap.get("gaps"):
            md.append("### Remaining Gaps")
            md.append("")
            for item in final_gap.get("gaps", [])[:12]:
                md.append(f"- **{item.get('gap')}** ({item.get('severity')}): {item.get('detail')}")
            md.append("")
        if final_gap.get("actions"):
            md.append("### Actions")
            md.append("")
            for action in final_gap.get("actions", [])[:12]:
                md.append(f"- {action}")
            md.append("")
    else:
        md.append("Router-level gap controller was skipped for this evidence type or disabled.")
        md.append("")

    md += [
        "## Findings Summary",
        "",
        "```json",
        json.dumps(summarize_reports(json_reports), indent=2, default=str)[:25000],
        "```",
        "",
    ]
    with md_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(md).rstrip() + "\n")
    return json_path, md_path


def main() -> int:
    args = parse_args()
    evidence_path = Path(args.evidence).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not evidence_path.exists():
        print(f"[ERROR] Evidence file not found: {evidence_path}")
        return 1

    evidence_type = detect_evidence_type(evidence_path, args.type)
    command = build_command(args, evidence_type)

    print("=" * 64)
    print("PHANTOM DFIR - Unified Router")
    print("=" * 64)
    print(f"Evidence type : {evidence_type}")
    print(f"Evidence path : {evidence_path}")
    print(f"Output dir    : {output_dir}")
    print("Routed command:")
    print("  " + " ".join(command))
    print("=" * 64)

    if args.dry_run:
        return 0

    started = time.time()
    returncode, stdout = stream_command(command, ROOT, timeout=args.timeout)

    returncode, stdout, report_paths, json_reports, gap_trace = evidence_gap_controller(
        evidence_type=evidence_type,
        command=command,
        output_dir=output_dir,
        initial_started=started,
        initial_returncode=returncode,
        initial_stdout=stdout,
        args=args,
    )
    summary = summarize_reports(json_reports)

    prompt = make_unified_prompt(evidence_type, evidence_path, summary)
    llm_status, llm_text = llm_invoke_text(prompt, args)

    unified_json, unified_md = write_unified_reports(
        output_dir=output_dir,
        evidence_path=evidence_path,
        evidence_type=evidence_type,
        command=command,
        returncode=returncode,
        report_paths=report_paths,
        json_reports=json_reports,
        llm_status=llm_status,
        llm_text=llm_text,
        stdout_tail=stdout,
        gap_trace=gap_trace,
    )

    print("=" * 64)
    print("PHANTOM ROUTER COMPLETE")
    print("=" * 64)
    print(f"Child return code : {returncode}")
    print(f"Reports found     : {len(report_paths)}")
    if gap_trace:
        final_gap = gap_trace[-1]
        print(f"Gap controller    : {len(gap_trace)} iteration(s), confidence={final_gap.get('confidence')}")
    print(f"Unified JSON      : {unified_json}")
    print(f"Unified MD        : {unified_md}")
    if llm_status != "ok":
        print(f"Unified LLM       : {llm_status} - {llm_text[:200]}")
    return returncode


if __name__ == "__main__":
    sys.exit(main())
