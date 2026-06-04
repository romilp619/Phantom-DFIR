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


def compact_value(value: Any, depth: int = 0, max_list: int = 8) -> Any:
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
        return value[:1200] + ("..." if len(value) > 1200 else "")
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
    if len(payload) > 45000:
        payload = payload[:45000] + "\n...TRUNCATED..."
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

    report_paths = extract_report_paths(stdout)
    report_paths.extend(scan_fresh_reports(output_dir, started))
    report_paths = unique_existing(report_paths)
    json_reports = load_json_reports(report_paths)
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
    )

    print("=" * 64)
    print("PHANTOM ROUTER COMPLETE")
    print("=" * 64)
    print(f"Child return code : {returncode}")
    print(f"Reports found     : {len(report_paths)}")
    print(f"Unified JSON      : {unified_json}")
    print(f"Unified MD        : {unified_md}")
    if llm_status != "ok":
        print(f"Unified LLM       : {llm_status} - {llm_text[:200]}")
    return returncode


if __name__ == "__main__":
    sys.exit(main())
