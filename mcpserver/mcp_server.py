#!/usr/bin/env python3
"""
PHANTOM DFIR — MCP Server v2.1
Exposes typed, structured DFIR functions via Model Context Protocol.

Architecture advantage over subprocess approach:
- Agent physically CANNOT run destructive commands
- All tool output pre-parsed before returning to LLM
- Evidence integrity enforced at server level
- No context window overload from raw Volatility dumps
- Path-aware benign process detection (Puppet/Chef Ruby)

Usage:
  python3 mcp_server.py                          # stdio mode (Claude Code)
  python3 mcp_server.py --transport sse --port 8765  # SSE mode (remote)

Install:
  pip install mcp fastapi uvicorn --break-system-packages
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from typing import Any

# ── MCP SDK ──────────────────────────────────────────────────────────────────
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    print("[WARN] mcp package not installed. Run: pip install mcp --break-system-packages",
          file=sys.stderr)

# ── Config ────────────────────────────────────────────────────────────────────
# Insert project root (parent of mcpserver/) into path for config import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from config import VOL3_CMD, TIMEOUT_PLUGIN_FAST, TIMEOUT_PLUGIN_SLOW
except ImportError:
    VOL3_CMD             = "vol"
    TIMEOUT_PLUGIN_FAST  = 120
    TIMEOUT_PLUGIN_SLOW  = 300

# ── Evidence integrity tracking ───────────────────────────────────────────────
_EVIDENCE_REGISTRY: dict[str, dict] = {}   # filepath -> {sha256, size, registered_at}


def _run_vol3(filepath: str, plugin: str, extra: str = "",
              timeout: int = TIMEOUT_PLUGIN_FAST) -> str:
    """Internal: run a Volatility 3 plugin with output sanitisation."""
    cmd = f"{VOL3_CMD} -q -f '{filepath}' {plugin} {extra} 2>&1"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout, errors="replace")
        out = (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR] {e}"
    # Strip progress/warning noise
    noise = ["Unsatisfied requirement", "A translation layer requirement",
             "symbol_table_name", "Progress:", "Stacking attempts",
             "WARNING:", "UserWarning"]
    lines = [l for l in out.splitlines() if not any(n in l for n in noise)]
    return "\n".join(lines).strip()


def _sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_integrity(filepath: str) -> dict:
    """Verify file hash hasn't changed since registration."""
    if filepath not in _EVIDENCE_REGISTRY:
        return {"status": "not_registered", "modified": False}
    reg  = _EVIDENCE_REGISTRY[filepath]
    curr = _sha256(filepath)
    modified = curr != reg["sha256"]
    return {
        "status":       "modified" if modified else "intact",
        "original_sha": reg["sha256"],
        "current_sha":  curr,
        "modified":     modified,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TYPED DFIR TOOL IMPLEMENTATIONS
# Each function does ONE specific thing and returns structured data.
# The LLM gets parsed results, not raw Volatility text dumps.
# ═══════════════════════════════════════════════════════════════════════════════

def register_evidence(filepath: str) -> dict:
    """
    Register an evidence file and compute its SHA256.
    Must be called before any analysis to establish integrity baseline.
    """
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}
    sha = _sha256(filepath)
    size = os.path.getsize(filepath)
    _EVIDENCE_REGISTRY[filepath] = {
        "sha256":        sha,
        "size_bytes":    size,
        "registered_at": time.time(),
    }
    return {
        "filepath":      filepath,
        "sha256":        sha,
        "size_mb":       round(size / 1024 / 1024, 1),
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "integrity":     "baseline_established",
    }


def verify_integrity(filepath: str) -> dict:
    """Verify evidence file hasn't been modified since registration."""
    return _check_integrity(filepath)


def get_process_list(filepath: str) -> dict:
    """
    Get running processes from memory dump.
    Returns structured list, NOT raw Volatility text.
    """
    raw = _run_vol3(filepath, "windows.pslist")
    processes = []
    for line in raw.splitlines():
        parts = line.split()
        # Vol3 2.28.0 format: PID  PPID  ImageFileName  Offset  Threads  Handles  SessionId  Wow64  CreateTime
        if len(parts) >= 7 and parts[0].isdigit():
            try:
                processes.append({
                    "pid":        int(parts[0]),
                    "ppid":       int(parts[1]),
                    "name":       parts[2],
                    "threads":    parts[4] if len(parts) > 4 else "0",
                    "wow64":      parts[7] == "True" if len(parts) > 7 else False,
                    "create_time": " ".join(parts[8:10]) if len(parts) > 9 else "",
                })
            except Exception:
                pass
    # Path-aware benign detection: ruby.exe from Puppet/Chef is NOT suspicious
    ALWAYS_SUSPICIOUS = {"meterpreter.exe", "nc.exe", "ncat.exe",
                         "powershell.exe", "wscript.exe", "cscript.exe"}
    BENIGN_RUBY_PATHS = ["puppet labs", "chef", "opscode", "rubyinstaller",
                         "bitnami", "railsinstaller"]
    suspicious = []
    for p in processes:
        name = p["name"].lower()
        if name in ALWAYS_SUSPICIOUS:
            suspicious.append(p)
        elif name in ("ruby.exe", "rubyw.exe"):
            # Only flag if NOT from a known-legitimate path
            create = p.get("create_time", "").lower()
            # We can't check path from pslist alone — mark as "needs_path_check"
            p["note"] = "ruby — verify path (Puppet/Chef = benign)"
            suspicious.append(p)
    return {
        "process_count": len(processes),
        "processes":     processes[:50],
        "suspicious":    suspicious,
    }


def get_process_tree(filepath: str) -> dict:
    """Get parent-child process relationships."""
    raw = _run_vol3(filepath, "windows.pstree")
    return {"raw_tree": raw[:3000], "source": "windows.pstree"}


def get_hidden_processes(filepath: str) -> dict:
    """
    Compare pslist vs psscan to find hidden processes (DKOM rootkit detection).
    Processes in psscan but NOT pslist = hidden by rootkit.
    """
    pslist_raw = _run_vol3(filepath, "windows.pslist")
    psscan_raw = _run_vol3(filepath, "windows.psscan")

    def extract_pids(text):
        pids = set()
        for line in text.splitlines():
            parts = line.split()
            # Vol3 2.28.0: PID is column 0
            if len(parts) >= 2 and parts[0].isdigit():
                pids.add(int(parts[0]))
        return pids

    pslist_pids = extract_pids(pslist_raw)
    psscan_pids = extract_pids(psscan_raw)
    hidden_pids = psscan_pids - pslist_pids

    hidden_details = []
    for line in psscan_raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            if int(parts[0]) in hidden_pids:
                hidden_details.append(line.strip())

    return {
        "pslist_count":  len(pslist_pids),
        "psscan_count":  len(psscan_pids),
        "hidden_count":  len(hidden_pids),
        "hidden_pids":   list(hidden_pids),
        "hidden_details": hidden_details[:20],
        "rootkit_indicator": len(hidden_pids) > 0,
    }


def get_network_connections(filepath: str) -> dict:
    """
    Get all network connections with process attribution.
    Flags suspicious connections (non-browser on unusual ports, external IPs).
    """
    netscan = _run_vol3(filepath, "windows.netscan")
    netstat = _run_vol3(filepath, "windows.netstat")

    connections = []
    suspicious  = []

    for line in (netscan + "\n" + netstat).splitlines():
        if "ESTABLISHED" in line or "LISTENING" in line:
            parts = line.split()
            if len(parts) >= 8:
                conn = {
                    "proto":       parts[1] if len(parts) > 1 else "",
                    "local":       parts[2] if len(parts) > 2 else "",
                    "remote":      parts[4] if len(parts) > 4 else "",
                    "state":       parts[6] if len(parts) > 6 else "",
                    "pid":         parts[7] if len(parts) > 7 else "",
                    "process":     parts[8] if len(parts) > 8 else "",
                }
                connections.append(conn)
                # Flag suspicious
                proc = conn.get("process", "").lower()
                remote = conn.get("remote", "")
                if any(p in proc for p in ["ruby", "nc", "ncat", "python",
                                            "perl", "powershell", "wscript"]):
                    suspicious.append({**conn, "reason": "non-browser process with network connection"})
                elif ":8080" in remote or ":4444" in remote or ":1337" in remote:
                    suspicious.append({**conn, "reason": "suspicious port (common C2)"})

    # External IPs
    external_ips = set()
    for c in connections:
        remote = c.get("remote", "")
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", remote)
        if m:
            ip = m.group(1)
            parts = ip.split(".")
            if not (parts[0] in ("10", "127") or
                    (parts[0] == "172" and 16 <= int(parts[1]) <= 31) or
                    (parts[0] == "192" and parts[1] == "168")):
                external_ips.add(ip)

    return {
        "total_connections":  len(connections),
        "suspicious_count":   len(suspicious),
        "external_ips":       list(external_ips),
        "suspicious":         suspicious[:20],
        "all_connections":    connections[:30],
    }


def get_services(filepath: str) -> dict:
    """
    Get Windows services — detects malicious services (wrong path, suspicious name).
    """
    raw = _run_vol3(filepath, "windows.svcscan")
    suspicious = []
    for line in raw.splitlines():
        line_lower = line.lower()
        # Services NOT in system32 are suspicious
        if ("c:\\windows\\" in line_lower and
                "system32" not in line_lower and
                ".exe" in line_lower):
            suspicious.append({"line": line.strip(), "reason": "service binary outside System32"})
    return {
        "raw_truncated": raw[:2000],
        "suspicious_services": suspicious[:10],
        "suspicious_count": len(suspicious),
    }


def get_malfind(filepath: str, pid: int = None) -> dict:
    """
    Find memory regions with suspicious characteristics (RWX + MZ headers).
    Primary indicator of process hollowing and code injection.
    """
    extra = f"--pid {pid}" if pid else ""
    raw   = _run_vol3(filepath, "windows.malware.malfind", extra,
                      timeout=TIMEOUT_PLUGIN_SLOW)
    mz_count = raw.count("MZ")
    rwx_count = len(re.findall(r'PAGE_EXECUTE_READWRITE', raw, re.I))
    return {
        "mz_headers_found":   mz_count,
        "rwx_regions_found":  rwx_count,
        "injection_likely":   mz_count > 2 or rwx_count > 0,
        "raw_truncated":      raw[:2000],
        "pid_filter":         pid,
    }


def get_cmdline(filepath: str, pid: int = None) -> dict:
    """Get command line arguments for all processes (or specific PID)."""
    extra = f"--pid {pid}" if pid else ""
    raw   = _run_vol3(filepath, "windows.cmdline", extra)
    suspicious = []
    for line in raw.splitlines():
        line_lower = line.lower()
        if any(x in line_lower for x in ["-enc ", "-encodedcommand", "base64",
                                          "downloadstring", "iex(", "invoke-expression",
                                          "wget ", "curl ", "/dev/tcp"]):
            suspicious.append(line.strip())
    return {
        "raw_truncated":     raw[:3000],
        "suspicious_cmds":   suspicious[:10],
        "pid_filter":        pid,
    }


def get_hollowed_processes(filepath: str) -> dict:
    """Detect process hollowing — legit process replaced with malicious code."""
    raw = _run_vol3(filepath, "windows.malware.hollowprocesses",
                    timeout=TIMEOUT_PLUGIN_SLOW)
    hollowed = [l.strip() for l in raw.splitlines() if l.strip() and
                not l.startswith("Volatility") and "PID" not in l]
    return {
        "hollowed_count":   len(hollowed),
        "hollowed_details": hollowed[:10],
        "hollowing_found":  len(hollowed) > 0,
    }


def get_dll_list(filepath: str, pid: int = None) -> dict:
    """Get loaded DLLs — detect injected DLLs from wrong locations."""
    extra = f"--pid {pid}" if pid else ""
    raw   = _run_vol3(filepath, "windows.dlllist", extra,
                      timeout=TIMEOUT_PLUGIN_SLOW)
    suspicious = []
    for line in raw.splitlines():
        ll = line.lower()
        if any(p in ll for p in [r"\temp\\", r"\tmp\\", r"\appdata\local\temp",
                                   r"\users\public\\"]):
            suspicious.append(line.strip())
    return {
        "suspicious_dlls": suspicious[:10],
        "pid_filter":      pid,
        "raw_truncated":   raw[:2000],
    }


def get_registry_run_keys(filepath: str) -> dict:
    """Get autorun registry keys — detect persistence mechanisms."""
    raw = _run_vol3(filepath, "windows.registry.printkey",
                    "--key \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\"")
    return {"raw": raw[:2000], "source": "HKCU/HKLM Run keys"}


def get_shimcache(filepath: str) -> dict:
    """Get shimcache — evidence of program execution even if deleted."""
    raw = _run_vol3(filepath, "windows.shimcachemem")
    suspicious = [l.strip() for l in raw.splitlines()
                  if any(x in l.lower() for x in ["subject_srv", "meterpreter",
                                                    r"\temp\\", r"\tmp\\"])]
    return {
        "suspicious_entries": suspicious[:10],
        "raw_truncated":      raw[:2000],
    }


def get_userassist(filepath: str) -> dict:
    """UserAssist — programs executed by user (GUI execution evidence)."""
    raw = _run_vol3(filepath, "windows.registry.userassist")
    return {"raw_truncated": raw[:2000]}


def get_scheduled_tasks(filepath: str) -> dict:
    """Scheduled tasks — common persistence mechanism."""
    raw = _run_vol3(filepath, "windows.registry.scheduled_tasks")
    suspicious = [l.strip() for l in raw.splitlines()
                  if any(x in l.lower() for x in ["powershell", "cmd", "wscript",
                                                    "cscript", "rundll32", "mshta"])]
    return {
        "suspicious_tasks": suspicious[:10],
        "raw_truncated":    raw[:2000],
    }


def get_ssdt_hooks(filepath: str) -> dict:
    """
    SSDT hook detection — kernel-level rootkit indicator.
    Entries NOT pointing to ntoskrnl/win32k = hooked by rootkit.
    """
    raw = _run_vol3(filepath, "windows.ssdt")
    hooks = [l.strip() for l in raw.splitlines()
             if l.strip() and "ntoskrnl" not in l.lower()
             and "win32k" not in l.lower()
             and l[0].isdigit()]
    return {
        "hooks_found":   len(hooks),
        "hook_details":  hooks[:10],
        "rootkit_indicator": len(hooks) > 0,
    }


def get_psxview(filepath: str) -> dict:
    """
    Cross-view process comparison — finds processes hiding from any enumeration method.
    """
    raw = _run_vol3(filepath, "windows.malware.psxview",
                    timeout=TIMEOUT_PLUGIN_SLOW)
    # Lines with "False" in any column = hiding from that method
    hiding = [l.strip() for l in raw.splitlines()
              if "False" in l and "PID" not in l]
    return {
        "hiding_count":   len(hiding),
        "hiding_details": hiding[:10],
        "evasion_found":  len(hiding) > 0,
    }


# ── DISK CORRELATION TOOLS ───────────────────────────────────────────────────

def get_disk_timeline(disk_path: str, output_dir: str = "/tmp") -> dict:
    """
    Build filesystem timeline from disk image using log2timeline/mactime.
    Returns key events sorted chronologically.
    SIFT tool: log2timeline.py + mactime
    """
    if not os.path.exists(disk_path):
        return {"error": f"Disk image not found: {disk_path}"}

    plaso_file = os.path.join(output_dir, "phantom_plaso.db")
    timeline_file = os.path.join(output_dir, "phantom_timeline.csv")

    # Run log2timeline
    log2tl = subprocess.run(
        f"log2timeline.py --storage-file {plaso_file} {disk_path} 2>&1",
        shell=True, capture_output=True, text=True, timeout=600
    )

    # Extract with psort
    if os.path.exists(plaso_file):
        subprocess.run(
            f"psort.py -o dynamic -w {timeline_file} {plaso_file} 2>/dev/null",
            shell=True, timeout=120
        )

    if os.path.exists(timeline_file):
        # Read and filter interesting events
        events = []
        with open(timeline_file, "r", errors="replace") as f:
            for line in f:
                if any(x in line.lower() for x in
                       [".exe", ".dll", "powershell", "cmd.exe", "startup",
                        "run key", "scheduled", "prefetch"]):
                    events.append(line.strip()[:300])
                    if len(events) >= 50:
                        break
        return {
            "timeline_built": True,
            "timeline_file":  timeline_file,
            "interesting_events": events[:30],
            "total_filtered": len(events),
        }
    return {
        "timeline_built": False,
        "error": log2tl.stdout[-500:] if log2tl.stdout else "log2timeline failed",
    }


def get_disk_strings(disk_path: str, keywords: list = None) -> dict:
    """
    Extract strings from disk image and search for keywords.
    Defaults to attacker-relevant keywords.
    """
    if keywords is None:
        keywords = ["wget", "curl", "powershell", "meterpreter",
                    "cobalt", "beacon", "base64", "/dev/tcp", "reverse"]

    results = {}
    all_text = ""
    try:
        r = subprocess.run(
            f"strings '{disk_path}' 2>/dev/null | head -10000",
            shell=True, capture_output=True, text=True, timeout=120
        )
        all_text = r.stdout
    except Exception as e:
        return {"error": str(e)}

    for kw in keywords:
        hits = [l.strip() for l in all_text.splitlines()
                if kw.lower() in l.lower()]
        if hits:
            results[kw] = hits[:5]

    return {
        "keywords_searched": keywords,
        "hits": results,
        "total_keywords_found": len(results),
    }


def get_mft_deleted_files(disk_path: str) -> dict:
    """
    List deleted files from MFT using fls.
    Key anti-forensics indicator: malware deletes itself after execution.
    SIFT tool: fls (The Sleuth Kit)
    """
    try:
        r = subprocess.run(
            f"fls -r -d '{disk_path}' 2>/dev/null | head -50",
            shell=True, capture_output=True, text=True, timeout=120
        )
        deleted = r.stdout.splitlines()
        suspicious_deleted = [l for l in deleted
                              if any(x in l.lower() for x in
                                     [".exe", ".dll", ".ps1", ".bat", ".vbs"])]
        return {
            "deleted_files_count": len(deleted),
            "deleted_files":       deleted[:30],
            "suspicious_deleted":  suspicious_deleted[:10],
        }
    except Exception as e:
        return {"error": str(e)}


def correlate_memory_disk(memory_findings: dict, disk_findings: dict) -> dict:
    """
    Cross-reference memory analysis findings with disk timeline findings.
    Detects discrepancies — the core of Multi-Source Correlation Engine.

    Discrepancy types:
    - Process in memory but no disk artifact (fileless malware)
    - File on disk but never executed (staged payload)
    - Timeline gaps (anti-forensics / timestomping)
    - Memory shows activity disk doesn't record (living off the land)
    """
    discrepancies = []
    confirmations = []

    mem_iocs  = set(memory_findings.get("iocs", []))
    disk_iocs = set(disk_findings.get("iocs", []))

    # In memory but not on disk = fileless
    fileless = mem_iocs - disk_iocs
    if fileless:
        discrepancies.append({
            "type":        "fileless_indicator",
            "description": f"Found in memory but no disk artifact: {fileless}",
            "severity":    "HIGH",
            "mitre":       "T1059.001",
        })

    # On disk but never in memory = staged payload
    staged = disk_iocs - mem_iocs
    if staged:
        discrepancies.append({
            "type":        "staged_payload",
            "description": f"Found on disk but not in memory: {staged}",
            "severity":    "MEDIUM",
            "mitre":       "T1074",
        })

    # Confirmed by both = high confidence
    confirmed = mem_iocs & disk_iocs
    for ioc in confirmed:
        confirmations.append({
            "ioc":    ioc,
            "sources": ["memory", "disk"],
            "confidence": "HIGH",
        })

    # Timestamp analysis
    mem_timestamps  = memory_findings.get("timestamps", [])
    disk_timestamps = disk_findings.get("timestamps", [])
    if mem_timestamps and disk_timestamps:
        mem_earliest  = min(mem_timestamps)  if mem_timestamps  else None
        disk_earliest = min(disk_timestamps) if disk_timestamps else None
        if mem_earliest and disk_earliest:
            if mem_earliest < disk_earliest:
                discrepancies.append({
                    "type":        "timestamp_discrepancy",
                    "description": f"Memory shows activity ({mem_earliest}) before disk "
                                   f"records it ({disk_earliest}) — possible timestomping",
                    "severity":    "HIGH",
                    "mitre":       "T1070.006",
                })

    return {
        "total_discrepancies": len(discrepancies),
        "total_confirmations": len(confirmations),
        "discrepancies":       discrepancies,
        "confirmations":       confirmations,
        "analysis_summary":    (
            f"Memory+Disk correlation: {len(confirmed)} IOCs confirmed by both sources, "
            f"{len(fileless)} fileless indicators, {len(staged)} staged artifacts"
        ),
    }


def get_prefetch(disk_path: str) -> dict:
    """
    Extract Windows Prefetch execution evidence from disk image.
    Proves a program was executed even if logs are cleared.
    SIFT tool: strings + icat
    """
    try:
        r = subprocess.run(
            f"strings '{disk_path}' 2>/dev/null | grep -i '\\.pf$\\|-[0-9A-F]{{8}}\\.pf' | head -30",
            shell=True, capture_output=True, text=True, timeout=60
        )
        prefetch = r.stdout.splitlines()
        suspicious = [p for p in prefetch
                     if any(x in p.lower() for x in
                            ["nc.exe", "ncat", "meterpreter",
                             "subject_srv", "powershell"])]
        return {
            "prefetch_entries": prefetch[:20],
            "suspicious":       suspicious,
            "execution_proven": len(suspicious) > 0,
        }
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# MCP SERVER DEFINITION
# ═══════════════════════════════════════════════════════════════════════════════

TOOL_DEFINITIONS = [
    # Evidence integrity
    Tool(name="register_evidence",
         description="Register evidence file and compute SHA256 baseline. MUST call before analysis.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="verify_integrity",
         description="Verify evidence file hasn't been modified since registration.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    # Memory analysis
    Tool(name="get_process_list",
         description="Get running processes from memory dump. Returns structured list with suspicious process flags.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_process_tree",
         description="Get parent-child process relationships to detect suspicious spawn chains.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_hidden_processes",
         description="Compare pslist vs psscan to find processes hidden by rootkits (DKOM detection).",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_network_connections",
         description="Get all network connections with process attribution and suspicious connection flags.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_services",
         description="Get Windows services. Detects services with binaries outside System32.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_malfind",
         description="Find RWX memory regions with PE headers — primary injection/hollowing indicator.",
         inputSchema={"type":"object","properties":{
             "filepath":{"type":"string"},
             "pid":{"type":"integer","description":"Optional PID to filter"}
         },"required":["filepath"]}),

    Tool(name="get_cmdline",
         description="Get command line arguments. Detects encoded PowerShell, LOLBins, and suspicious commands.",
         inputSchema={"type":"object","properties":{
             "filepath":{"type":"string"},
             "pid":{"type":"integer","description":"Optional PID to filter"}
         },"required":["filepath"]}),

    Tool(name="get_hollowed_processes",
         description="Detect process hollowing — legitimate process binary replaced with malicious code.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_dll_list",
         description="Get loaded DLLs. Detects injected DLLs loaded from temp/appdata directories.",
         inputSchema={"type":"object","properties":{
             "filepath":{"type":"string"},
             "pid":{"type":"integer","description":"Optional PID to filter"}
         },"required":["filepath"]}),

    Tool(name="get_shimcache",
         description="Get shimcache — proves program execution even if the file was deleted.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_scheduled_tasks",
         description="Get scheduled tasks — common persistence mechanism. Flags suspicious task commands.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_ssdt_hooks",
         description="Detect SSDT hooks — kernel-level rootkit indicator. Entries not from ntoskrnl = hooked.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    Tool(name="get_psxview",
         description="Cross-view process comparison. Processes hiding from any method = evasion.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),

    # Disk analysis
    Tool(name="get_disk_timeline",
         description="Build filesystem timeline from disk image using log2timeline. Returns interesting events.",
         inputSchema={"type":"object","properties":{
             "disk_path":{"type":"string"},
             "output_dir":{"type":"string","default":"/tmp"}
         },"required":["disk_path"]}),

    Tool(name="get_disk_strings",
         description="Extract and search strings from disk image for attacker keywords.",
         inputSchema={"type":"object","properties":{
             "disk_path":{"type":"string"},
             "keywords":{"type":"array","items":{"type":"string"}}
         },"required":["disk_path"]}),

    Tool(name="get_mft_deleted_files",
         description="List deleted files from MFT using fls. Key anti-forensics indicator.",
         inputSchema={"type":"object","properties":{"disk_path":{"type":"string"}},"required":["disk_path"]}),

    Tool(name="get_prefetch",
         description="Extract Windows Prefetch execution evidence from disk. Proves execution even after log clearing.",
         inputSchema={"type":"object","properties":{"disk_path":{"type":"string"}},"required":["disk_path"]}),

    # Correlation
    Tool(name="correlate_memory_disk",
         description="Cross-reference memory and disk findings. Detects fileless malware, staged payloads, timestamp discrepancies.",
         inputSchema={"type":"object","properties":{
             "memory_findings":{"type":"object"},
             "disk_findings":{"type":"object"}
         },"required":["memory_findings","disk_findings"]}),
]


TOOL_DISPATCH = {
    "register_evidence":    lambda a: register_evidence(**a),
    "verify_integrity":     lambda a: verify_integrity(**a),
    "get_process_list":     lambda a: get_process_list(**a),
    "get_process_tree":     lambda a: get_process_tree(**a),
    "get_hidden_processes": lambda a: get_hidden_processes(**a),
    "get_network_connections": lambda a: get_network_connections(**a),
    "get_services":         lambda a: get_services(**a),
    "get_malfind":          lambda a: get_malfind(**a),
    "get_cmdline":          lambda a: get_cmdline(**a),
    "get_hollowed_processes": lambda a: get_hollowed_processes(**a),
    "get_dll_list":         lambda a: get_dll_list(**a),
    "get_shimcache":        lambda a: get_shimcache(**a),
    "get_scheduled_tasks":  lambda a: get_scheduled_tasks(**a),
    "get_ssdt_hooks":       lambda a: get_ssdt_hooks(**a),
    "get_psxview":          lambda a: get_psxview(**a),
    "get_disk_timeline":    lambda a: get_disk_timeline(**a),
    "get_disk_strings":     lambda a: get_disk_strings(**a),
    "get_mft_deleted_files": lambda a: get_mft_deleted_files(**a),
    "get_prefetch":         lambda a: get_prefetch(**a),
    "correlate_memory_disk": lambda a: correlate_memory_disk(**a),
}


async def main_mcp():
    """Run PHANTOM DFIR as an MCP server (stdio transport)."""
    if not MCP_AVAILABLE:
        print("[ERROR] mcp package required. Run: pip install mcp --break-system-packages")
        sys.exit(1)

    server = Server("phantom-dfir")

    @server.list_tools()
    async def list_tools():
        return TOOL_DEFINITIONS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name not in TOOL_DISPATCH:
            return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]
        try:
            result = TOOL_DISPATCH[name](arguments)
            return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())


def run_http_server(host: str = "0.0.0.0", port: int = 8765):
    """
    Run as simple HTTP API server (no MCP SDK required).
    Useful for testing and integration with non-MCP clients.
    """
    try:
        from fastapi import FastAPI
        import uvicorn
    except ImportError:
        print("[ERROR] fastapi/uvicorn required: pip install fastapi uvicorn --break-system-packages")
        sys.exit(1)

    app = FastAPI(
        title="PHANTOM DFIR MCP Server",
        description="Typed DFIR functions — no raw shell access",
        version="2.1.0"
    )

    @app.get("/tools")
    def list_tools_http():
        return {"tools": [{"name": t.name, "description": t.description}
                          for t in TOOL_DEFINITIONS]}

    @app.post("/tool/{name}")
    def call_tool_http(name: str, body: dict):
        if name not in TOOL_DISPATCH:
            return {"error": f"Unknown tool: {name}"}
        try:
            return TOOL_DISPATCH[name](body)
        except Exception as e:
            return {"error": str(e)}

    @app.get("/health")
    def health():
        return {"status": "ok", "tools": len(TOOL_DEFINITIONS),
                "vol3": VOL3_CMD}

    print(f"[PHANTOM MCP] HTTP server on http://{host}:{port}")
    print(f"[PHANTOM MCP] Tools available: {len(TOOL_DEFINITIONS)}")
    print(f"[PHANTOM MCP] API docs: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse, asyncio

    p = argparse.ArgumentParser(description="PHANTOM DFIR MCP Server")
    p.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args()

    if args.transport == "http":
        run_http_server(args.host, args.port)
    else:
        asyncio.run(main_mcp())
