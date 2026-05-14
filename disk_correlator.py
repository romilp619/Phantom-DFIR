"""
PHANTOM DFIR — Disk Correlation Agent v3.0
INTELLIGENT correlation — eliminates false positives by design.

Key improvements over v2:
- Path-based legitimacy: same name in wrong location = suspicious
- Process tree analysis: flags unusual parent-child relationships
- Obfuscation detection: mixed-case wget/curl, encoded commands
- Known-good path allowlist: System32, Program Files = benign
- Smart staged payload detection: only flags truly suspicious files
- No hardcoded case-specific allowlists — works on any disk image

Usage:
  python3 disk_correlator.py -m memory.img -d disk.E01
  python3 disk_correlator.py -m memory.img -d disk.E01 -o /cases/001/
  python3 disk_correlator.py -m memory.img -d disk.E01 --no-timeline
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from config import VOL3_CMD, TIMEOUT_PLUGIN_FAST, TIMEOUT_PLUGIN_SLOW, OLLAMA_MODEL
    from agents.collector import detect_engines
except ImportError:
    VOL3_CMD            = "vol"
    TIMEOUT_PLUGIN_FAST = 120
    TIMEOUT_PLUGIN_SLOW = 300
    OLLAMA_MODEL        = "qwen2.5:14b"

SEP   = "═" * 60
_lock = Lock()


def run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout, errors="replace")
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR] {e}"


def sha256_fast(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def info(m):
    with _lock: print(f"  → {m}", flush=True)

def ok(m):
    with _lock: print(f"  ✓ {m}", flush=True)

def warn(m):
    with _lock: print(f"  ⚠  {m}", flush=True)

def section(t):
    with _lock: print(f"\n{SEP}\n  {t}\n{SEP}", flush=True)


# ─────────────────────────────────────────────────────────────
# PATH-BASED LEGITIMACY ENGINE
# The core insight: location matters more than filename.
# svchost.exe in System32 = benign
# svchost.exe in C:\Users\Public\ = malware
# ─────────────────────────────────────────────────────────────
BENIGN_PATHS = [
    r'c:\\windows\\system32\\',
    r'c:\\windows\\syswow64\\',
    r'c:\\windows\\systemapps\\',
    r'c:\\program files\\',
    r'c:\\program files (x86)\\',
    r'c:\\programdata\\microsoft\\windows defender\\',
    r'c:\\windows\\winsxs\\',
    r'c:\\windows\\microsoft.net\\',
]

SUSPICIOUS_PATHS = [
    r'c:\\users\\.*\\appdata\\local\\temp\\',
    r'c:\\users\\.*\\appdata\\roaming\\',
    r'c:\\users\\public\\',
    r'c:\\windows\\temp\\',
    r'c:\\temp\\',
    r'c:\\programdata\\(?!microsoft)',
    r'^c:\\[^\\]+\.(exe|dll|ps1|bat)$',  # root of C: drive
]

# Windows core process names that should ONLY run from System32
SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe",
    "winlogon.exe", "services.exe", "wininit.exe", "spoolsv.exe",
    "explorer.exe", "taskhostw.exe", "conhost.exe", "dwm.exe",
    "fontdrvhost.exe", "fontdrvhost.ex",
}

# Known forensic / investigation tools — never flag these
FORENSIC_TOOLS = {
    "subject_srv.exe",   # F-Response subject
    "winpmem.exe",       # Memory acquisition
    "dumpit.exe",        # Memory acquisition
    "rammap.exe",        # Sysinternals RAM map
    "procmon.exe",       # Sysinternals Process Monitor
    "procexp.exe",       # Sysinternals Process Explorer
    "autoruns.exe",      # Sysinternals Autoruns
    "volatility.exe",    # Volatility
    "ftkimager.exe",     # FTK Imager
    "magnet.exe",        # Magnet forensics
}

# Known management/orchestration tools
MANAGEMENT_TOOLS = {
    "ruby.exe", "rubyw.exe",    # Puppet/Chef/Ansible
    "puppet.exe",               # Puppet
    "chef-client.exe",          # Chef
    "ansible.exe",              # Ansible
    "python.exe", "pythonw.exe",# Python automation
}


def is_path_suspicious(path):
    """Return (is_suspicious, reason) based on file path."""
    if not path or path in ("-", "N/A", ""):
        return False, ""
    path_lower = path.lower().replace("/", "\\")

    # Check for masquerading: system process name in wrong location
    fname = os.path.basename(path_lower)
    if fname in SYSTEM_PROCESS_NAMES:
        in_system32 = any(re.search(p, path_lower) for p in BENIGN_PATHS[:2])
        if not in_system32:
            return True, f"MASQUERADING: {fname} running from non-system path: {path}"

    # Check for known suspicious paths
    for pat in SUSPICIOUS_PATHS:
        if re.search(pat, path_lower):
            return True, f"SUSPICIOUS PATH: {path}"

    return False, ""


def is_benign_process(name, path, cmdline):
    """Return True if this process is known-good."""
    name_lower = name.lower()
    path_lower = (path or "").lower()
    cmdline_lower = (cmdline or "").lower()

    # Forensic tools — always benign in IR context
    if name_lower in FORENSIC_TOOLS:
        return True

    # Management tools from known paths
    if name_lower in MANAGEMENT_TOOLS:
        if "program files" in path_lower:
            return True

    # Standard Windows processes from System32
    if name_lower in SYSTEM_PROCESS_NAMES:
        if any(p in path_lower for p in ["system32", "syswow64"]):
            return True

    # VMware tools
    if "vmware" in path_lower or "vmware" in name_lower:
        return True

    # Windows Defender
    if "windows defender" in path_lower or name_lower in {
        "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe",
        "msseces.exe", "msascuil.exe"
    }:
        return True

    return False


# ─────────────────────────────────────────────────────────────
# OBFUSCATION DETECTOR
# Catches mixed-case wget/curl, encoded PowerShell, etc.
# ─────────────────────────────────────────────────────────────
def detect_obfuscation(text):
    """Find obfuscated download/execution commands."""
    findings = []

    # Mixed-case wget/curl (case-alternating = bypass detection)
    mixedcase = re.findall(
        r'\b(?:[Ww][Gg][Ee][Tt]|[Cc][Uu][Rr][Ll]|'
        r'[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll])\b',
        text)
    # Filter: flag only if NOT all-caps or all-lowercase
    for m in mixedcase:
        if m not in (m.upper(), m.lower()):
            findings.append({
                "type":   "mixed_case_obfuscation",
                "match":  m,
                "note":   f"Mixed-case '{m}' — bypasses case-sensitive string detection",
                "mitre":  "T1027.010",
                "score":  20,
            })

    # Repeated obfuscated pattern (x12 = scripted)
    repeat_matches = re.findall(
        r'(?:[xX][wW][gG][eE][tT]|[xX][cC][uU][rR][lL])', text)
    if len(repeat_matches) >= 3:
        findings.append({
            "type":  "repeated_obfuscated_downloader",
            "count": len(repeat_matches),
            "note":  f"Obfuscated downloader pattern repeated {len(repeat_matches)}x — likely script loop",
            "mitre": "T1105",
            "score": 30,
        })

    # PowerShell encoded command
    enc_ps = re.findall(
        r'-[Ee](?:nc(?:odedCommand)?|[Ee])\s+[A-Za-z0-9+/=]{20,}', text)
    for m in enc_ps:
        findings.append({
            "type":  "powershell_encoded",
            "match": m[:60],
            "note":  "PowerShell encoded command — content hidden from plain-text scanning",
            "mitre": "T1059.001",
            "score": 25,
        })

    # Base64 in command
    b64_cmds = re.findall(
        r'(?:base64\s+-d|FromBase64String|[Cc]onvert\s*::\s*[Ff]rom[Bb]ase64)', text)
    for m in b64_cmds:
        findings.append({
            "type":  "base64_decode_command",
            "match": m[:60],
            "note":  "Base64 decode in command — payload encoding",
            "mitre": "T1140",
            "score": 20,
        })

    return findings


# ─────────────────────────────────────────────────────────────
# PROCESS TREE ANALYZER
# Detects unusual parent-child relationships
# ─────────────────────────────────────────────────────────────
def analyze_process_tree(pstree_raw):
    """Parse process tree and flag suspicious relationships."""
    findings = []
    processes = {}

    # Parse pstree output into structured data
    for line in pstree_raw.splitlines():
        # Extract PID, PPID, name, path from pstree line
        m = re.match(
            r'\*+\s+(\d+)\s+(\d+)\s+(\S+)\s+\S+\s+\d+\s+-\s+\d+\s+'
            r'(?:True|False)\s+\S+\s+(?:N/A|\S+)\s+(\S+)\s+(.*)',
            line)
        if m:
            pid, ppid, name = int(m.group(1)), int(m.group(2)), m.group(3)
            path    = m.group(4) if m.group(4) != "-" else ""
            cmdline = m.group(5) if m.group(5) else ""
            processes[pid] = {
                "pid":     pid,
                "ppid":    ppid,
                "name":    name.lower(),
                "path":    path,
                "cmdline": cmdline,
            }

    # Check for suspicious parent-child relationships
    UNUSUAL_PARENTS = {
        # Process name → suspicious if spawned by these parents
        "powershell.exe": {"winword.exe", "excel.exe", "outlook.exe",
                           "acrord32.exe", "chrome.exe", "firefox.exe",
                           "iexplore.exe", "mshta.exe", "wscript.exe",
                           "cscript.exe"},
        "cmd.exe":        {"winword.exe", "excel.exe", "outlook.exe",
                           "acrord32.exe"},
        "wscript.exe":    {"winword.exe", "excel.exe", "outlook.exe"},
        "mshta.exe":      {"winword.exe", "excel.exe", "outlook.exe",
                           "svchost.exe"},
    }

    for pid, proc in processes.items():
        parent = processes.get(proc["ppid"])
        if not parent:
            continue

        child_name  = proc["name"]
        parent_name = parent["name"]

        suspicious_parents = UNUSUAL_PARENTS.get(child_name, set())
        if parent_name in suspicious_parents:
            findings.append({
                "type":   "suspicious_parent_child",
                "child":  f"{child_name} (PID {pid})",
                "parent": f"{parent_name} (PID {proc['ppid']})",
                "note":   f"{parent_name} spawned {child_name} — "
                          f"common malware execution pattern",
                "mitre":  "T1059",
                "score":  35,
            })
            warn(f"SUSPICIOUS SPAWN: {parent_name} → {child_name}")

        # PowerShell with no arguments = possible interactive/encoded session
        if child_name == "powershell.exe":
            cmd = proc["cmdline"].strip()
            # Only the executable path, nothing else
            if cmd in (
                '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
                "powershell.exe", ""
            ):
                findings.append({
                    "type":   "powershell_no_args",
                    "pid":    pid,
                    "parent": f"{parent_name} (PID {proc['ppid']})",
                    "note":   f"PowerShell PID {pid} launched with NO arguments "
                              f"by {parent_name} — possible interactive or "
                              f"stdin-fed session",
                    "mitre":  "T1059.001",
                    "score":  15,
                })
                warn(f"PowerShell PID {pid} — no arguments (parent: {parent_name})")

        # Path-based masquerading check
        sus, reason = is_path_suspicious(proc.get("path", ""))
        if sus and not is_benign_process(
                child_name, proc.get("path", ""), proc.get("cmdline", "")):
            findings.append({
                "type":   "path_masquerading",
                "process": f"{child_name} (PID {pid})",
                "path":   proc.get("path", ""),
                "note":   reason,
                "mitre":  "T1036",
                "score":  40,
            })
            warn(f"PATH MASQUERADE: {reason}")

    return findings, processes


# ─────────────────────────────────────────────────────────────
# MEMORY ARTIFACT EXTRACTION
# ─────────────────────────────────────────────────────────────
def extract_memory_artifacts(memory_path, engines):
    section("MEMORY ARTIFACT EXTRACTION")
    artifacts = {
        "processes":       [],
        "process_map":     {},
        "network":         [],
        "services":        [],
        "commands":        [],
        "iocs":            set(),
        "timestamps":      [],
        "tree_findings":   [],
        "raw":             {},
    }

    vol3 = engines.get("vol3")
    if not vol3:
        warn("No Volatility engine — strings fallback")
        artifacts["iocs"] = list(artifacts["iocs"])
        return artifacts

    tasks = {
        "pslist":    (f"{VOL3_CMD} -q -f '{memory_path}' windows.pslist 2>&1",
                      TIMEOUT_PLUGIN_FAST),
        "pstree":    (f"{VOL3_CMD} -q -f '{memory_path}' windows.pstree 2>&1",
                      TIMEOUT_PLUGIN_FAST),
        "netscan":   (f"{VOL3_CMD} -q -f '{memory_path}' windows.netscan 2>&1",
                      TIMEOUT_PLUGIN_FAST),
        "netstat":   (f"{VOL3_CMD} -q -f '{memory_path}' windows.netstat 2>&1",
                      TIMEOUT_PLUGIN_FAST),
        "svcscan":   (f"{VOL3_CMD} -q -f '{memory_path}' windows.svcscan 2>&1",
                      TIMEOUT_PLUGIN_FAST),
        "cmdline":   (f"{VOL3_CMD} -q -f '{memory_path}' windows.cmdline 2>&1",
                      TIMEOUT_PLUGIN_FAST),
        "shimcache": (f"{VOL3_CMD} -q -f '{memory_path}' windows.shimcachemem 2>&1",
                      TIMEOUT_PLUGIN_FAST),
        "malfind":   (f"{VOL3_CMD} -q -f '{memory_path}' windows.malware.malfind 2>&1",
                      TIMEOUT_PLUGIN_SLOW),
    }

    print(f"\n  Firing {len(tasks)} Volatility plugins simultaneously...", flush=True)
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(run, cmd, timeout): name
                   for name, (cmd, timeout) in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                artifacts["raw"][name] = result
                ok(f"memory:{name} ({time.time()-t0:.1f}s)")
            except Exception as e:
                warn(f"memory:{name} failed: {e}")

    info(f"All memory plugins done in {time.time()-t0:.1f}s")

    # ── Parse pslist — Vol3 format: PID PPID ImageFileName Offset Threads ...
    # Header line: "PID  PPID  ImageFileName  Offset(V) ..."
    for line in artifacts["raw"].get("pslist", "").splitlines():
        parts = line.split()
        # Skip header, progress lines, and blank lines
        if len(parts) < 3:
            continue
        # Vol3: col0=PID, col1=PPID, col2=ImageFileName
        if parts[0].isdigit() and parts[1].isdigit():
            pid, ppid, name = int(parts[0]), int(parts[1]), parts[2]
            artifacts["processes"].append({
                "name": name,
                "pid":  pid,
                "ppid": ppid,
            })
            if name.lower() not in SYSTEM_PROCESS_NAMES:
                artifacts["iocs"].add(name.lower())

    # ── Analyze process tree for suspicious relationships ──────
    pstree_raw = artifacts["raw"].get("pstree", "")
    tree_findings, proc_map = analyze_process_tree(pstree_raw)
    artifacts["tree_findings"] = tree_findings
    artifacts["process_map"]   = proc_map

    # ── Parse network — external connections only ─────────────
    # Vol3 netscan format:
    # Offset  Proto  LocalAddr  LocalPort  ForeignAddr  ForeignPort  State  PID  Owner  Created
    net_raw = (artifacts["raw"].get("netscan", "") + "\n" +
               artifacts["raw"].get("netstat", ""))
    for line in net_raw.splitlines():
        if "ESTABLISHED" not in line and "CLOSE_WAIT" not in line:
            continue
        parts = line.split()
        # Find ForeignAddr and ForeignPort: they sit before the State column
        # Locate State column index
        try:
            state_idx = next(i for i, p in enumerate(parts)
                             if p in ("ESTABLISHED", "CLOSE_WAIT", "LISTEN", "CLOSE"))
        except StopIteration:
            continue
        # ForeignAddr is 2 cols before State, ForeignPort is 1 col before
        if state_idx < 2:
            continue
        foreign_addr = parts[state_idx - 2]
        # foreign_addr might be "IP" or "IP:port" or "*" — handle both
        ip = foreign_addr.split(":")[0] if ":" in foreign_addr else foreign_addr
        # Validate it looks like an IP
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            continue
        # Skip RFC1918 / loopback / wildcard
        if ip in ("0.0.0.0", "*") or re.match(
                r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", ip):
            continue
        port = parts[state_idx - 1]
        artifacts["network"].append({
            "ip":   ip,
            "port": port,
            "line": line.strip()[:200],
        })
        artifacts["iocs"].add(ip)

    # ── Parse services — flag non-System32 binary paths ───────
    # Vol3 svcscan format has "Running"/"Auto" (not Vol2's "SERVICE_RUNNING")
    for line in artifacts["raw"].get("svcscan", "").splitlines():
        line_lower = line.lower()
        # Match both Vol3 ("running", "auto") and Vol2 ("service_running") formats
        if any(kw in line_lower for kw in (
                "running", "auto_start", "service_running", "service_auto_start")):
            # Flag services running from suspicious paths
            for pat in SUSPICIOUS_PATHS:
                if re.search(pat, line_lower):
                    artifacts["services"].append(line.strip())
                    warn(f"Suspicious service path: {line.strip()[:100]}")
                    break

    # ── Parse cmdline — flag suspicious commands ──────────────
    cmdline_raw = artifacts["raw"].get("cmdline", "")
    for line in cmdline_raw.splitlines():
        line_lower = line.lower()

        # Encoded PowerShell
        if re.search(r'-e(?:nc(?:odedcommand)?|[ec])\s+[a-z0-9+/=]{20,}',
                     line_lower):
            artifacts["commands"].append({
                "type": "encoded_powershell",
                "line": line.strip(),
                "mitre": "T1059.001",
                "score": 30,
            })
            warn(f"ENCODED POWERSHELL: {line.strip()[:100]}")

        # Download cradles
        elif re.search(
            r'(downloadstring|downloadfile|invoke-webrequest|'
            r'webclient|wget|curl.*http)', line_lower):
            artifacts["commands"].append({
                "type": "download_cradle",
                "line": line.strip(),
                "mitre": "T1105",
                "score": 25,
            })
            warn(f"DOWNLOAD CRADLE: {line.strip()[:100]}")

        # IEX / Invoke-Expression
        elif re.search(r'iex\s*\(|invoke-expression', line_lower):
            artifacts["commands"].append({
                "type": "invoke_expression",
                "line": line.strip(),
                "mitre": "T1059.001",
                "score": 25,
            })
            warn(f"INVOKE-EXPRESSION: {line.strip()[:100]}")

    # ── Parse shimcache timestamps ────────────────────────────
    for line in artifacts["raw"].get("shimcache", "").splitlines():
        m = re.search(r'(\d{4}-\d{2}-\d{2})', line)
        if m:
            artifacts["timestamps"].append(m.group(1))

    artifacts["iocs"] = list(artifacts["iocs"])
    info(f"Processes: {len(artifacts['processes'])}")
    info(f"External connections: {len(artifacts['network'])}")
    info(f"Suspicious services: {len(artifacts['services'])}")
    info(f"Suspicious commands: {len(artifacts['commands'])}")
    info(f"Process tree findings: {len(artifacts['tree_findings'])}")
    return artifacts


# ─────────────────────────────────────────────────────────────
# DISK ARTIFACT EXTRACTION
# ─────────────────────────────────────────────────────────────
def extract_disk_artifacts(disk_path, output_dir, no_timeline=False):
    section("DISK ARTIFACT EXTRACTION")
    artifacts = {
        "files":           [],
        "deleted":         [],
        "prefetch":        [],
        "registry":        [],
        "timeline":        [],
        "obfuscation":     [],
        "iocs":            set(),
        "timestamps":      [],
        "raw":             {},
    }
    os.makedirs(output_dir, exist_ok=True)

    # All keywords in ONE strings pass
    keywords = [
        "meterpreter", "cobalt", "beacon", "mimikatz", "sekurlsa",
        "lsadump", "invoke-", "downloadstring", "iex(", "base64",
        "powershell -e", "-encodedcommand", "reflectiveloader",
        "shellcode", "exploit", "backdoor", "reverse.shell",
    ]
    kw_pattern = "|".join(keywords)

    # Mixed-case obfuscation patterns
    obfusc_pattern = (r'[Ww][Gg][Ee][Tt]|[Cc][Uu][Rr][Ll]|'
                      r'[xX][wW][gG][eE][tT]|[xX][cC][uU][rR][lL]')

    disk_tasks = {
        # Active executables NOT in known-good paths
        "fls_sus": (
            f"fls -r '{disk_path}' 2>/dev/null | "
            f"grep -iE '\\.(exe|dll|ps1|bat|vbs|sh|rb|py)' | "
            f"grep -ivE '(windows|system32|syswow64|program.files|"
            f"winsxs|microsoft\\.net|assembly)' | head -100",
            120),
        # Deleted files
        "fls_deleted": (
            f"fls -r -d '{disk_path}' 2>/dev/null | head -100",
            120),
        # Malware keyword strings — one pass
        "strings_malware": (
            f"strings '{disk_path}' 2>/dev/null | "
            f"grep -iE '{kw_pattern}' | head -50",
            90),
        # Obfuscation strings
        "strings_obfusc": (
            f"strings '{disk_path}' 2>/dev/null | "
            f"grep -E '{obfusc_pattern}' | head -30",
            60),
        # Prefetch
        "prefetch": (
            f"strings '{disk_path}' 2>/dev/null | "
            f"grep -iE '\\.(pf|prefetch)|PREFETCH' | head -30",
            60),
        # Partition info
        "mmls": (
            f"mmls '{disk_path}' 2>/dev/null | head -10",
            30),
        # Registry run keys
        "registry_run": (
            f"strings '{disk_path}' 2>/dev/null | "
            f"grep -iE '(CurrentVersion\\\\Run|Startup|RunOnce)' | "
            f"grep -ivE '(^HKLM|^HKCU|software\\\\microsoft\\\\windows)' "
            f"| head -20",
            60),
    }

    print(f"\n  Firing {len(disk_tasks)} disk tasks simultaneously...", flush=True)
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=len(disk_tasks)) as ex:
        futures = {ex.submit(run, cmd, timeout): name
                   for name, (cmd, timeout) in disk_tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                artifacts["raw"][name] = result
                ok(f"disk:{name} ({time.time()-t0:.1f}s)")
            except Exception as e:
                warn(f"disk:{name} failed: {e}")

    info(f"All disk tasks done in {time.time()-t0:.1f}s")

    # ── Parse suspicious active files ─────────────────────────
    for line in artifacts["raw"].get("fls_sus", "").splitlines():
        if "[TIMEOUT" in line:
            continue
        artifacts["files"].append(line.strip())
        m = re.search(r'([A-Za-z0-9_\-]+\.(exe|dll|ps1|bat|vbs))', line, re.I)
        if m:
            name = m.group(1).lower()
            # Only add if not a known forensic/management tool
            if name not in FORENSIC_TOOLS and name not in MANAGEMENT_TOOLS:
                artifacts["iocs"].add(name)
    ok(f"Suspicious-path files: {len(artifacts['files'])}")

    # ── Parse deleted files ───────────────────────────────────
    for line in artifacts["raw"].get("fls_deleted", "").splitlines():
        artifacts["deleted"].append(line.strip())
        m = re.search(r'([A-Za-z0-9_\-]+\.(exe|dll|ps1))', line, re.I)
        if m:
            name = m.group(1).lower()
            if name not in FORENSIC_TOOLS:
                artifacts["iocs"].add(name)
                warn(f"Deleted executable: {name}")
    ok(f"Deleted files: {len(artifacts['deleted'])}")

    # ── Parse malware strings ─────────────────────────────────
    malware_hits = artifacts["raw"].get("strings_malware", "")
    for kw in keywords:
        if kw.lower() in malware_hits.lower():
            artifacts["iocs"].add(kw)
            warn(f"Malware string on disk: '{kw}'")

    # ── Parse obfuscation strings ─────────────────────────────
    obfusc_raw = artifacts["raw"].get("strings_obfusc", "")
    if obfusc_raw.strip() and "[TIMEOUT" not in obfusc_raw:
        obfusc_findings = detect_obfuscation(obfusc_raw)
        artifacts["obfuscation"] = obfusc_findings
        for f in obfusc_findings:
            warn(f"OBFUSCATION on disk: {f['note']}")

    # ── Parse prefetch ────────────────────────────────────────
    for line in artifacts["raw"].get("prefetch", "").splitlines():
        m = re.search(r'([A-Z0-9_\-]+\.EXE)', line)
        if m:
            artifacts["prefetch"].append(m.group(1))
    ok(f"Prefetch entries: {len(artifacts['prefetch'])}")

    # ── Timeline (optional, non-blocking) ────────────────────
    if not no_timeline:
        plaso_db   = os.path.join(output_dir, "phantom_disk.plaso")
        timeline_f = os.path.join(output_dir, "phantom_disk_timeline.csv")

        if not os.path.exists(plaso_db):
            info("log2timeline running in background — won't block analysis")
            subprocess.Popen(
                f"log2timeline.py --storage-file '{plaso_db}' '{disk_path}' "
                f"> /tmp/l2t.log 2>&1", shell=True)
        elif not os.path.exists(timeline_f):
            run(f"psort.py -o dynamic -w '{timeline_f}' '{plaso_db}' 2>/dev/null",
                timeout=300)

        if os.path.exists(timeline_f):
            keywords_tl = [".exe", "Run", "Startup", "Prefetch",
                           "PowerShell", "cmd.exe"]
            with open(timeline_f, "r", errors="replace") as f:
                for line in f:
                    if any(kw.lower() in line.lower() for kw in keywords_tl):
                        artifacts["timeline"].append(line.strip()[:200])
                        m = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                        if m:
                            artifacts["timestamps"].append(m.group(1))
                        if len(artifacts["timeline"]) >= 100:
                            break
            ok(f"Timeline events: {len(artifacts['timeline'])}")
    else:
        info("Timeline skipped (--no-timeline)")

    artifacts["iocs"] = list(artifacts["iocs"])
    info(f"Disk IOCs (suspicious only): {len(artifacts['iocs'])}")
    return artifacts


# ─────────────────────────────────────────────────────────────
# CORRELATION ENGINE — INTELLIGENT
# ─────────────────────────────────────────────────────────────
def correlate(mem, disk, memory_path, disk_path):
    section("INTELLIGENT CORRELATION ENGINE")

    mem_iocs  = set(i.lower() for i in mem.get("iocs",  []))
    disk_iocs = set(i.lower() for i in disk.get("iocs", []))

    results = {
        "confirmed_both":          [],
        "fileless_indicators":     [],
        "staged_payloads":         [],
        "timestamp_discrepancies": [],
        "execution_chain":         [],
        "process_anomalies":       [],
        "obfuscation_findings":    [],
        "total_score":             0,
        "score_breakdown":         [],
    }

    def add_score(points, reason):
        results["total_score"] += points
        results["score_breakdown"].append(
            f"+{points}: {reason}")

    # ── Process tree anomalies (highest confidence) ───────────
    for finding in mem.get("tree_findings", []):
        results["process_anomalies"].append(finding)
        add_score(finding.get("score", 10),
                  f"Process anomaly: {finding['note'][:60]}")
        warn(f"PROCESS ANOMALY: {finding['note'][:80]}")

    # ── Obfuscation on disk ───────────────────────────────────
    for finding in disk.get("obfuscation", []):
        results["obfuscation_findings"].append(finding)
        add_score(finding.get("score", 15),
                  f"Obfuscation: {finding['note'][:60]}")

    # ── Suspicious commands in memory ────────────────────────
    for cmd in mem.get("commands", []):
        results["process_anomalies"].append({
            "type":  cmd.get("type", "suspicious_command"),
            "note":  cmd.get("line", "")[:150],
            "mitre": cmd.get("mitre", "T1059"),
            "score": cmd.get("score", 20),
        })
        add_score(cmd.get("score", 20),
                  f"Suspicious command: {cmd.get('type', '')}")

    # ── Confirmed by both sources ─────────────────────────────
    # Only flag non-trivial IOCs confirmed in both
    # Expand skip set: system procs + forensic tools + Defender + legit apps
    DEFENDER_PROCS = {
        "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe", "msascuil.exe",
        "msseces.exe", "antimalware service executable",
    }
    SKIP = SYSTEM_PROCESS_NAMES | FORENSIC_TOOLS | MANAGEMENT_TOOLS | DEFENDER_PROCS
    both = mem_iocs & disk_iocs
    for ioc in both:
        if ioc in SKIP or len(ioc) < 5:
            continue
        # Skip generic keywords
        if ioc in {"wget", "curl", "base64", "python", "perl", "ruby",
                   "msmpeng", "nissrv", "defender"}:
            continue
        results["confirmed_both"].append({
            "ioc":        ioc,
            "confidence": "HIGH",
            "note":       "Found in BOTH memory and disk",
        })
        add_score(10, f"Confirmed both: {ioc}")
    info(f"Confirmed by both: {len(results['confirmed_both'])}")

    # ── Fileless: memory only, NOT a system process ───────────
    # NOTE: fls only scans suspicious paths — standard Windows apps
    # (chrome, notepad, powershell etc.) won't appear in disk_iocs
    # even though they exist on disk. Only flag as fileless if:
    #   1. Not a known Windows/system binary
    #   2. Not a known legitimate application
    #   3. Name is actually unusual/suspicious
    KNOWN_LEGIT_BINS = {
        # Windows built-ins
        "powershell.exe", "notepad.exe", "cmd.exe", "msiexec.exe",
        "regsvr32.exe", "rundll32.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "explorer.exe", "taskmgr.exe", "regedit.exe",
        "mmc.exe", "control.exe", "dllhost.exe", "conhost.exe",
        "defrag.exe", "logonui.exe", "userinit.exe", "ctfmon.exe",
        "sihost.exe", "taskhostw.exe", "searchui.exe", "audiodg.exe",
        "fontdrvhost.exe", "dwm.exe", "winlogon.exe", "lsass.exe",
        "wmiprvse.exe", "msdtc.exe", "rdpclip.exe", "rdpinput.exe",
        "tabtip.exe", "tabtip32.exe", "plasrv.exe",
        # VMware tools (common in lab VMs)
        "vmtoolsd.exe", "vmacthlp.exe", "vmwaretray.exe", "vmwareuser.exe",
        # Common legit apps
        "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe",
        "notepad++.exe", "putty.exe", "skypehost.exe", "onedrive.exe",
        "mstsc.exe",
        # Windows Defender
        "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe", "msascuil.exe",
    }

    for ioc in (mem_iocs - disk_iocs):
        if ioc in SKIP or len(ioc) < 5:
            continue
        if not ioc.endswith((".exe", ".dll", ".ps1")):
            continue
        # Skip known-legitimate binaries — fls just didn't scan their path
        if ioc in KNOWN_LEGIT_BINS:
            continue
        # Skip if name matches standard Windows patterns
        if re.match(r'^(svc|win|ms|nt|wer|wmi|cls|com)', ioc):
            continue
        results["fileless_indicators"].append({
            "ioc":   ioc,
            "note":  "In memory but NO disk artifact — fileless indicator",
            "mitre": "T1059",
        })
        add_score(15, f"Fileless: {ioc}")
        warn(f"FILELESS: {ioc}")
    info(f"Fileless indicators: {len(results['fileless_indicators'])}")

    # ── Staged payloads: disk only, suspicious path ───────────
    # Only flag files from suspicious paths, not all unrun executables
    sus_disk_files = [
        f for f in disk.get("files", [])
        if any(re.search(p, f.lower()) for p in SUSPICIOUS_PATHS)
    ]
    for f in sus_disk_files[:20]:
        m = re.search(r'([A-Za-z0-9_\-]+\.(exe|ps1|bat|vbs))', f, re.I)
        if m:
            name = m.group(1).lower()
            if name not in SKIP and name not in FORENSIC_TOOLS:
                results["staged_payloads"].append({
                    "ioc":   name,
                    "path":  f[:150],
                    "note":  "Executable in suspicious path not seen in memory",
                    "mitre": "T1074",
                })
                add_score(8, f"Staged payload: {name}")
    info(f"Staged payloads (suspicious paths): {len(results['staged_payloads'])}")

    # ── Deleted but still running ─────────────────────────────
    deleted_names = set()
    for d in disk.get("deleted", []):
        m = re.search(r'([A-Za-z0-9_\-]+\.(exe|dll|ps1))', d, re.I)
        if m:
            deleted_names.add(m.group(1).lower())

    mem_proc_names = set(p["name"].lower() for p in mem.get("processes", []))
    for name in (deleted_names & mem_proc_names):
        if name in SKIP or name in FORENSIC_TOOLS:
            continue
        results["fileless_indicators"].append({
            "ioc":   name,
            "note":  "DELETED from disk but still RUNNING in memory",
            "mitre": "T1036",
        })
        add_score(25, f"Deleted+running: {name}")
        warn(f"CRITICAL: {name} deleted but still running!")

    # ── Timestamp analysis ────────────────────────────────────
    mem_ts  = sorted(set(mem.get("timestamps",  [])))
    disk_ts = sorted(set(disk.get("timestamps", [])))

    if mem_ts and disk_ts and mem_ts[0] < disk_ts[0]:
        results["timestamp_discrepancies"].append({
            "type":   "memory_before_disk",
            "memory": mem_ts[0],
            "disk":   disk_ts[0],
            "note":   f"Memory activity {mem_ts[0]} predates disk "
                      f"timeline {disk_ts[0]} — possible timestomping",
            "mitre":  "T1070.006",
        })
        add_score(20, "Timestamp discrepancy")

    # ── Execution chain ───────────────────────────────────────
    for entry in mem.get("raw", {}).get("shimcache", "").splitlines()[:5]:
        if any(x in entry.lower() for x in [
            "temp", "appdata\\roaming", "public", "programdata"
        ]):
            results["execution_chain"].append({
                "source": "shimcache",
                "entry":  entry.strip()[:150],
                "note":   "Shimcache proves execution from suspicious path",
            })
            add_score(15, "Shimcache execution from suspicious path")

    info(f"Total suspicion score: {results['total_score']}")
    info(f"Score breakdown: {results['score_breakdown']}")
    return results


# ─────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────
def generate_report(memory_path, disk_path, mem_artifacts,
                    disk_artifacts, correlation,
                    output_dir, mem_hash, disk_hash):
    section("REPORT GENERATION")

    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    mem_base  = os.path.basename(memory_path).replace(".", "_")[:20]
    disk_base = os.path.basename(disk_path).replace(".", "_")[:20]
    prefix    = f"phantom_correlation_{mem_base}_{disk_base}_{ts}"

    mem_hash_after  = sha256_fast(memory_path)
    disk_hash_after = sha256_fast(disk_path)
    hashes_match    = (mem_hash == mem_hash_after and
                       disk_hash == disk_hash_after)

    score   = correlation["total_score"]
    verdict = ("HIGH CONFIDENCE COMPROMISE" if score >= 50 else
               "SUSPICIOUS — INVESTIGATE"   if score >= 20 else
               "LOW SUSPICION — LIKELY CLEAN")

    report = {
        "metadata": {
            "tool":      "PHANTOM DFIR Disk Correlator v3.0",
            "timestamp": datetime.now().isoformat(),
            "memory_image": {
                "path":    memory_path,
                "sha256":  mem_hash,
                "size_mb": round(os.path.getsize(memory_path)/1024/1024, 1),
            },
            "disk_image": {
                "path":    disk_path,
                "sha256":  disk_hash,
                "size_mb": round(os.path.getsize(disk_path)/1024/1024, 1),
            },
            "evidence_integrity": {
                "mode":              "read-only",
                "hashes_verified":   hashes_match,
                "spoliation_risk":   not hashes_match,
            },
        },
        "verdict":         verdict,
        "suspicion_score": score,
        "score_breakdown": correlation["score_breakdown"],
        "summary": {
            "process_anomalies":       len(correlation["process_anomalies"]),
            "obfuscation_findings":    len(correlation["obfuscation_findings"]),
            "confirmed_both":          len(correlation["confirmed_both"]),
            "fileless_indicators":     len(correlation["fileless_indicators"]),
            "staged_payloads":         len(correlation["staged_payloads"]),
            "timestamp_discrepancies": len(correlation["timestamp_discrepancies"]),
        },
        "process_anomalies":       correlation["process_anomalies"],
        "obfuscation_findings":    correlation["obfuscation_findings"],
        "confirmed_both":          correlation["confirmed_both"],
        "fileless_indicators":     correlation["fileless_indicators"],
        "staged_payloads":         correlation["staged_payloads"][:10],
        "timestamp_discrepancies": correlation["timestamp_discrepancies"],
        "execution_chain":         correlation["execution_chain"],
        "memory_stats": {
            "processes":         len(mem_artifacts["processes"]),
            "external_conns":    len(mem_artifacts["network"]),
            "suspicious_svcs":   len(mem_artifacts["services"]),
            "suspicious_cmds":   len(mem_artifacts["commands"]),
            "tree_findings":     len(mem_artifacts["tree_findings"]),
        },
        "disk_stats": {
            "suspicious_path_files": len(disk_artifacts["files"]),
            "deleted_files":         len(disk_artifacts["deleted"]),
            "prefetch_entries":      len(disk_artifacts["prefetch"]),
            "obfuscation_hits":      len(disk_artifacts["obfuscation"]),
        },
        "external_connections": [n["line"] for n in
                                  mem_artifacts["network"][:10]],
        "suspicious_commands":  [c.get("line", "")[:150]
                                  for c in mem_artifacts["commands"][:10]],
    }

    json_path = os.path.join(output_dir, f"{prefix}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    ok(f"JSON: {json_path}")

    # Markdown
    md = f"""# PHANTOM DFIR — Correlation Report v3.0

**Memory**: `{memory_path}` SHA256: `{mem_hash[:16]}...`
**Disk**:   `{disk_path}` SHA256: `{disk_hash[:16]}...`
**Date**: {datetime.now().isoformat()}
**Evidence Integrity**: {'✅ VERIFIED' if hashes_match else '❌ HASH MISMATCH'}

---

## Verdict: {verdict}
**Suspicion Score: {score}**

| Category | Count |
|----------|-------|
| 🔴 Process anomalies | {len(correlation['process_anomalies'])} |
| 🔴 Obfuscation on disk | {len(correlation['obfuscation_findings'])} |
| ✅ Confirmed both sources | {len(correlation['confirmed_both'])} |
| 🟡 Fileless indicators | {len(correlation['fileless_indicators'])} |
| 🟡 Staged payloads (suspicious paths) | {len(correlation['staged_payloads'])} |
| ⚠️ Timestamp discrepancies | {len(correlation['timestamp_discrepancies'])} |

### Score Breakdown
"""
    for s in correlation["score_breakdown"]:
        md += f"- {s}\n"

    md += "\n---\n\n## 🔴 Process Anomalies\n"
    for p in correlation["process_anomalies"][:10]:
        md += f"- **{p.get('type','')}**: {p.get('note','')[:150]} (MITRE: {p.get('mitre','')})\n"

    md += "\n---\n\n## 🔴 Obfuscation on Disk\n"
    for o in correlation["obfuscation_findings"][:10]:
        md += f"- **{o.get('type','')}**: {o.get('note','')[:150]} (MITRE: {o.get('mitre','')})\n"

    md += "\n---\n\n## ✅ Confirmed Both Sources\n"
    for c in correlation["confirmed_both"][:10]:
        md += f"- `{c['ioc']}` — {c['note']}\n"

    md += "\n---\n\n## 🟡 Fileless Indicators\n"
    for fi in correlation["fileless_indicators"][:10]:
        md += f"- `{fi['ioc']}` — {fi['note']} (MITRE: {fi.get('mitre','')})\n"

    if correlation["staged_payloads"]:
        md += "\n---\n\n## 🟡 Staged Payloads (Suspicious Paths)\n"
        for s in correlation["staged_payloads"][:10]:
            md += f"- `{s['ioc']}` — {s['note']}\n"

    if mem_artifacts["network"]:
        md += "\n---\n\n## 🌐 External Connections\n"
        for n in mem_artifacts["network"][:10]:
            md += f"- `{n['line'][:150]}`\n"

    md += f"\n---\n*PHANTOM DFIR v3.0 | Find Evil! Hackathon 2026*\n"

    md_path = os.path.join(output_dir, f"{prefix}.md")
    with open(md_path, "w") as f:
        f.write(md)
    ok(f"MD: {md_path}")
    return json_path, md_path


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="PHANTOM DFIR — Intelligent Disk Correlator v3.0",
        epilog="""
Examples:
  python3 disk_correlator.py -m memory.img -d disk.E01
  python3 disk_correlator.py -m memory.raw -d disk.E01 -o /cases/001/
  python3 disk_correlator.py -m memory.img -d disk.E01 --no-timeline
        """
    )
    p.add_argument("-m", "--memory",     required=True)
    p.add_argument("-d", "--disk",       required=True)
    p.add_argument("-o", "--output-dir", default=os.path.expanduser("~"))
    p.add_argument("--no-timeline",      action="store_true",
                   help="Skip log2timeline (recommended for triage)")
    args = p.parse_args()

    for path in [args.memory, args.disk]:
        if not os.path.exists(path):
            print(f"[ERROR] Not found: {path}")
            sys.exit(1)

    print("""
╔══════════════════════════════════════════════════════════════╗
║   PHANTOM DFIR — Intelligent Disk Correlator v3.0            ║
║   Path-based | Process Tree | Obfuscation Detection          ║
║   Find Evil! Hackathon 2026                                   ║
╚══════════════════════════════════════════════════════════════╝""")

    print(f"\n  Memory : {args.memory}")
    print(f"  Disk   : {args.disk}")
    print(f"  Output : {args.output_dir}")
    print(f"  Mode   : {'FAST (no timeline)' if args.no_timeline else 'FULL'}")

    t0 = time.time()

    # Hash both in parallel
    print("\n  Hashing evidence in parallel...", flush=True)
    with ThreadPoolExecutor(max_workers=2) as ex:
        mf = ex.submit(sha256_fast, args.memory)
        df = ex.submit(sha256_fast, args.disk)
        mem_hash  = mf.result()
        disk_hash = df.result()
    ok(f"Memory SHA256: {mem_hash[:32]}...")
    ok(f"Disk   SHA256: {disk_hash[:32]}...")

    # Detect engines
    engines = {}
    try:
        engines = detect_engines()
    except Exception:
        import shutil
        for v in ["vol", "vol3", "volatility3"]:
            if shutil.which(v):
                engines["vol3"] = shutil.which(v)
                break

    # Memory + disk extraction in parallel
    section("PARALLEL EXTRACTION")
    mem_result  = [None]
    disk_result = [None]

    def do_memory():
        mem_result[0] = extract_memory_artifacts(args.memory, engines)

    def do_disk():
        disk_result[0] = extract_disk_artifacts(
            args.disk, args.output_dir, args.no_timeline)

    with ThreadPoolExecutor(max_workers=2) as ex:
        mf = ex.submit(do_memory)
        df = ex.submit(do_disk)
        mf.result()
        df.result()

    extraction_time = time.time() - t0
    info(f"Extraction complete in {extraction_time:.1f}s")

    correlation = correlate(mem_result[0], disk_result[0],
                            args.memory, args.disk)

    json_path, md_path = generate_report(
        args.memory, args.disk,
        mem_result[0], disk_result[0],
        correlation, args.output_dir,
        mem_hash, disk_hash)

    elapsed = time.time() - t0
    score   = correlation["total_score"]
    verdict = ("HIGH CONFIDENCE COMPROMISE" if score >= 50 else
               "SUSPICIOUS — INVESTIGATE"   if score >= 20 else
               "LOW SUSPICION — LIKELY CLEAN")

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  COMPLETE in {elapsed:.0f}s
║  Verdict : {verdict}
║  Score   : {score} (breakdown in report)
║  JSON    : {os.path.basename(json_path)}
║  MD      : {os.path.basename(md_path)}
╚══════════════════════════════════════════════════════════════╝""")

    if correlation["process_anomalies"]:
        print(f"\n  🔴 PROCESS ANOMALIES ({len(correlation['process_anomalies'])}):")
        for p in correlation["process_anomalies"][:3]:
            print(f"     • {p.get('note','')[:80]}")
    if correlation["obfuscation_findings"]:
        print(f"\n  🔴 OBFUSCATION ({len(correlation['obfuscation_findings'])}):")
        for o in correlation["obfuscation_findings"][:3]:
            print(f"     • {o.get('note','')[:80]}")
    if correlation["fileless_indicators"]:
        print(f"\n  🟡 FILELESS ({len(correlation['fileless_indicators'])}):")
        for fi in correlation["fileless_indicators"][:3]:
            print(f"     • {fi['ioc']} — {fi['note'][:60]}")
    if mem_result[0]["network"]:
        print(f"\n  🌐 EXTERNAL CONNECTIONS ({len(mem_result[0]['network'])}):")
        for n in mem_result[0]["network"][:3]:
            print(f"     • {n['line'][:80]}")


if __name__ == "__main__":
    main()
