"""
PHANTOM DFIR — Attack Timeline Reconstructor v2.1
Extracts timestamped events from raw evidence and builds a
chronological attack timeline.

v2.0 — Dynamic interesting keywords from discovered IOCs
     — No hardcoded case-specific terms
v2.1 — Human-readable event description parsing
     — Raw plugin output transformed into forensic narratives
"""
import re
from datetime import datetime


# Base keywords that are always forensically interesting
BASE_INTERESTING = [
    "services.exe", "malfind", "shimcache", "userassist",
    "meterpreter", "mimikatz", "metasploit",
    "hashdump", "lsadump", "beacon", "cobalt",
]


def _build_interesting_keywords(raw_evidence: dict) -> list:
    """
    Dynamically build the interesting keywords list from evidence.
    Extracts: suspicious process names, external IPs, unusual ports.
    """
    keywords = list(BASE_INTERESTING)

    # Extract suspicious process names (non-standard Windows)
    pslist = raw_evidence.get("vol3:pslist", "")
    SYSTEM_PROCS = {
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "dwm.exe", "explorer.exe", "conhost.exe", "fontdrvhost.exe",
        "taskhostw.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe",
        "searchui.exe", "shellexperiencehost.exe", "wmiprvse.exe",
        "spoolsv.exe", "lsaiso.exe", "memory compression", "dllhost.exe",
        "msdtc.exe", "wudfhost.exe", "searchindexer.exe",
    }
    for line in pslist.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            proc_name = parts[2].lower()
            if (proc_name not in SYSTEM_PROCS and
                    not proc_name.startswith("svchost") and
                    proc_name.endswith(".exe") and
                    len(proc_name) > 3):
                keywords.append(proc_name.replace(".exe", ""))

    # Extract IPs from netscan (only non-local)
    for plugin in ["vol3:netscan", "vol3:netstat"]:
        text = raw_evidence.get(plugin, "")
        for ip in re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', text):
            if not ip.startswith(("0.", "127.", "255.")):
                keywords.append(ip)

    # Deduplicate
    return list(set(keywords))


def _is_interesting(line: str, keywords: list) -> bool:
    lower = line.lower()
    return any(k.lower() in lower for k in keywords)


def _parse_event_description(line: str, plugin: str) -> str:
    """
    Transform raw Volatility plugin output into a human-readable event description.
    Extracts key forensic details (process name, PID, path, IP, port) and
    constructs a concise narrative sentence.
    """
    line = line.strip()

    # ── Process list / pstree events ──────────────────────────────────────────
    if plugin in ("vol3:pslist", "vol3:psscan", "vol3:pstree",
                  "vol3:linux_pslist", "vol3:linux_pstree"):
        # Typical: PID  PPID  Name  ... timestamp
        # Or pstree: *** PID  PPID  Name  ...
        # Extract process name and PID
        clean = re.sub(r'^[\*\s]+', '', line)  # strip pstree indentation
        parts = clean.split()
        pid = ppid = proc_name = path = None
        for i, p in enumerate(parts):
            if p.isdigit() and pid is None:
                pid = p
            elif p.isdigit() and ppid is None:
                ppid = p
            elif '.exe' in p.lower() and proc_name is None:
                proc_name = p
                break
        # Try to find path
        path_m = re.search(r'(\\Device\\[^\s]+|[A-Z]:\\[^\s]+)', line)
        if path_m:
            path = path_m.group(1)
        if proc_name and pid:
            desc = f"Process '{proc_name}' (PID {pid}" + (f", PPID {ppid}" if ppid else "") + ") created"
            if path:
                desc += f" from {path}"
            return desc

    # ── Network connections ───────────────────────────────────────────────────
    if plugin in ("vol3:netscan", "vol3:netstat", "vol2:netscan",
                  "vol3:linux_sockstat"):
        # Typical: offset  proto  localIP  localPort  remoteIP  remotePort  state  PID  process
        proto_m = re.search(r'(TCPv[46]|UDPv[46]|TCP|UDP)', line)
        ip_pairs = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)', line)
        state_m = re.search(r'(ESTABLISHED|LISTENING|CLOSE_WAIT|TIME_WAIT|SYN_SENT|CLOSED)', line)
        proc_m = re.search(r'(\d+)\s+([\w\.]+\.exe)', line, re.I)
        if ip_pairs:
            proto = proto_m.group(1) if proto_m else "TCP"
            state = state_m.group(1) if state_m else "unknown"
            local = f"{ip_pairs[0][0]}:{ip_pairs[0][1]}" if len(ip_pairs) >= 1 else "?"
            remote = f"{ip_pairs[1][0]}:{ip_pairs[1][1]}" if len(ip_pairs) >= 2 else "*:*"
            proc_info = f" by '{proc_m.group(2)}' (PID {proc_m.group(1)})" if proc_m else ""
            return f"{proto} connection {local} → {remote} [{state}]{proc_info}"

    # ── Service events ────────────────────────────────────────────────────────
    if plugin in ("vol3:svcscan", "vol3:svclist", "vol2:svcscan"):
        # Extract service name and state
        svc_state_m = re.search(r'(SERVICE_RUNNING|SERVICE_STOPPED|SERVICE_PAUSED)', line)
        svc_start_m = re.search(r'(SERVICE_AUTO_START|SERVICE_DEMAND_START|SERVICE_DISABLED)', line)
        exe_m = re.search(r'([\w\-]+\.exe)', line, re.I)
        if exe_m:
            state = svc_state_m.group(1).replace('SERVICE_', '').lower() if svc_state_m else "registered"
            start = svc_start_m.group(1).replace('SERVICE_', '').lower().replace('_', '-') if svc_start_m else ""
            return f"Service '{exe_m.group(1)}' {state}" + (f" (start: {start})" if start else "")

    # ── Session events ────────────────────────────────────────────────────────
    if plugin == "vol3:sessions":
        parts = line.split()
        proc_m = re.search(r'([\w\.]+\.exe)', line, re.I)
        user_m = re.search(r'(\w+/\w+\$?)', line)
        if proc_m:
            user = f" as '{user_m.group(1)}'" if user_m else ""
            return f"Session: '{proc_m.group(1)}' started{user}"

    # ── UserAssist (program execution) ────────────────────────────────────────
    if plugin == "vol3:userassist":
        path_m = re.search(r'([\w\\:]+\.exe)', line, re.I)
        count_m = re.search(r'Count\s+(\d+)', line, re.I)
        if path_m:
            count = f" (run {count_m.group(1)}x)" if count_m else ""
            return f"UserAssist: '{path_m.group(1)}' executed{count}"
        # Registry key access
        reg_m = re.search(r'(ntuser\.dat\\[^\s]+)', line, re.I)
        if reg_m:
            return f"UserAssist registry: {reg_m.group(1)}"

    # ── Scheduled tasks ───────────────────────────────────────────────────────
    if plugin == "vol3:scheduled_tasks":
        # First meaningful field is usually the task name
        parts = line.split('\t')
        if parts:
            task_name = parts[0].strip()[:60]
            return f"Scheduled task: '{task_name}'"

    # ── Shimcache ─────────────────────────────────────────────────────────────
    if plugin in ("vol3:shimcachemem", "vol2:shimcache"):
        path_m = re.search(r'(\\Device\\[^\s]+|[A-Z]:\\[^\s]+)', line)
        if path_m:
            return f"Shimcache entry: {path_m.group(1)}"

    # ── Command line ──────────────────────────────────────────────────────────
    if plugin == "vol3:cmdline":
        pid_m = re.search(r'(\d+)', line)
        proc_m = re.search(r'([\w\.]+\.exe)', line, re.I)
        if proc_m:
            pid = f" (PID {pid_m.group(1)})" if pid_m else ""
            cmd = line.strip()[:120]
            return f"Command line{pid}: {cmd}"

    # ── psxview (cross-reference) ─────────────────────────────────────────────
    if plugin == "vol3:psxview":
        proc_m = re.search(r'([\w\.]+\.exe)', line, re.I)
        if proc_m:
            exit_m = re.search(r'True', line)
            return f"Process cross-ref: '{proc_m.group(1)}' " + ("exited" if exit_m else "active")

    # ── Fallback: truncate raw line ───────────────────────────────────────────
    return line[:150]


def extract_timestamps(raw_evidence: dict, keywords: list = None) -> list:
    """
    Scan all raw evidence for timestamp patterns near interesting artifacts.
    Returns list of {timestamp, event, event_raw, source, interesting} sorted chronologically.
    """
    if keywords is None:
        keywords = _build_interesting_keywords(raw_evidence)

    events = []
    ts_regex = re.compile(r"(20\d{2}-\d{2}-\d{2}[\s_T]\d{2}:\d{2}:\d{2})")

    for plugin, text in raw_evidence.items():
        for line in text.splitlines():
            m = ts_regex.search(line)
            if m:
                ts_str = m.group(1).replace("T", " ").replace("_", " ")
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    continue
                interesting = _is_interesting(line, keywords)
                parsed_desc = _parse_event_description(line, plugin)
                events.append({
                    "timestamp":   ts.isoformat(),
                    "event":       parsed_desc,
                    "event_raw":   line.strip()[:200],
                    "source":      plugin,
                    "interesting": interesting,
                })

    # Deduplicate and sort
    seen = set()
    unique = []
    for e in events:
        key = (e["timestamp"], e["event"][:80])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    unique.sort(key=lambda x: x["timestamp"])
    return unique


def filter_interesting(timeline: list) -> list:
    """Return only the events flagged as interesting."""
    return [e for e in timeline if e.get("interesting")]


def format_timeline_md(timeline: list) -> str:
    """Format timeline as markdown table with human-readable event descriptions."""
    if not timeline:
        return "_No timestamped events found._"
    lines = ["| Timestamp | Event | Source |",
             "|-----------|-------|--------|"]
    for e in timeline:
        ts  = e["timestamp"]
        evt = e["event"].replace("|", "\\|")[:120]
        src = e["source"]
        lines.append(f"| `{ts}` | {evt} | `{src}` |")
    return "\n".join(lines)
