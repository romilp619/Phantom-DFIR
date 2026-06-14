"""
PHANTOM DFIR - Evidence Agent v2.0
Targeted re-queries for specific PIDs, IPs, or filenames.
Called by the Skeptic agent to verify or refute each challenge.

v2.0 - Linux PID extraction support
     - Smarter source deduplication
"""
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import tools.vol3_tools as v3
import tools.vol2_tools as v2
from state import InvestigationState
from config import MAX_PARALLEL_WORKERS


def _extract_pid(ioc: str, raw_evidence: dict, os_type: str = "windows") -> list:
    """Find all PIDs matching the IOC name in pslist output."""
    pids = []

    if os_type == "linux":
        pslist_text = raw_evidence.get("vol3:linux_pslist", "")
    else:
        pslist_text = raw_evidence.get("vol3:pslist", "") or raw_evidence.get("vol2:pslist", "")

    ioc_lower = ioc.lower().replace(".exe", "")
    for line in pslist_text.splitlines():
        if ioc_lower in line.lower():
            # Volatility columns: PID, PPID, Name ... or Name, PID, PPID ...
            parts = line.split()
            for i, p in enumerate(parts):
                if p.isdigit() and int(p) > 0:
                    pids.append(int(p))
                    break
    return list(set(pids))


def _extract_ip(ioc: str) -> str:
    """Extract bare IP from IOC string like '172.16.4.10:8080'."""
    m = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ioc)
    return m.group(1) if m else ioc


def gather_targeted_evidence(filepath: str, hypothesis: dict,
                             raw_evidence: dict, os_type: str = "windows") -> dict:
    """
    Run targeted re-queries based on the hypothesis ioc and requires_verification list.
    Returns dict of source_name -> output snippet.
    """
    ioc   = hypothesis.get("ioc", "")
    phase = hypothesis.get("attack_phase", "")
    targeted = {}

    # Extract PIDs for process-based IOCs
    pids = []
    if any(x in ioc.lower() for x in [".exe", ".dll", ".sys"]):
        pids = _extract_pid(ioc, raw_evidence, os_type)

    # Extract IP for network IOCs
    ip = None
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ioc):
        ip = _extract_ip(ioc)

    tasks = {}

    if os_type == "linux":
        # Linux PID-targeted queries
        for pid in pids[:3]:
            tasks[f"vol3:linux_lsof[{pid}]"] = lambda p=pid: v3._vol3(
                filepath, "linux.lsof.Lsof", f"--pid {p}")
            tasks[f"vol3:linux_envars[{pid}]"] = lambda p=pid: v3._vol3(
                filepath, "linux.envars.Envars", f"--pid {p}")

        # Linux IP-targeted queries
        if ip:
            sockstat = raw_evidence.get("vol3:linux_sockstat", "")
            targeted[f"sockstat_filter[{ip}]"] = "\n".join(
                l for l in sockstat.splitlines() if ip in l)
    else:
        # Windows PID-targeted queries
        for pid in pids[:3]:
            tasks[f"vol3:malfind[{pid}]"]  = lambda p=pid: v3.malfind(filepath, p)
            tasks[f"vol3:dlllist[{pid}]"]  = lambda p=pid: v3.dlllist(filepath, p)
            tasks[f"vol3:cmdline[{pid}]"]  = lambda p=pid: v3._vol3(
                filepath, "windows.cmdline", f"--pid {p}")

        # IP-targeted queries
        if ip:
            ns_raw = raw_evidence.get("vol3:netscan", "")
            nt_raw = raw_evidence.get("vol3:netstat", "")
            v2_ns  = raw_evidence.get("vol2:netscan", "")
            targeted[f"netscan_filter[{ip}]"] = "\n".join(
                l for l in ns_raw.splitlines() if ip in l)
            targeted[f"netstat_filter[{ip}]"] = "\n".join(
                l for l in nt_raw.splitlines() if ip in l)
            if v2_ns:
                targeted[f"vol2_netscan_filter[{ip}]"] = "\n".join(
                    l for l in v2_ns.splitlines() if ip in l)

    # Phase-specific extras
    if phase == "CredentialAccess":
        tasks["vol2:hashdump"] = lambda: v2.hashdump(filepath)
        tasks["vol2:lsadump"]  = lambda: v2.lsadump(filepath)

    if phase in ("Persistence", "Execution"):
        shimcache = raw_evidence.get("vol3:shimcachemem") or raw_evidence.get("vol2:shimcache", "")
        targeted["shimcache_filter"] = "\n".join(
            l for l in shimcache.splitlines()
            if ioc.lower().replace(".exe", "") in l.lower())

    if phase == "C2" or any(p in ioc for p in ["8080", "4444", "1337"]):
        tasks["vol3:netscan_live"] = lambda: v3.netscan(filepath)

    # Service evidence for persistence
    if phase == "Persistence" or "srv" in ioc.lower():
        svc = raw_evidence.get("vol3:svcscan", "") or raw_evidence.get("vol2:svcscan", "")
        targeted["svcscan_filter"] = "\n".join(
            l for l in svc.splitlines()
            if ioc.lower().replace(".exe", "") in l.lower())

    # Run parallel tasks
    with ThreadPoolExecutor(max_workers=min(len(tasks) or 1, 8)) as ex:
        future_map = {ex.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                targeted[name] = future.result() or ""
            except Exception as e:
                targeted[name] = f"[ERROR] {e}"

    return targeted


def check_evidence_confirms(targeted: dict, ioc: str) -> list:
    """
    Check which targeted evidence sources actually confirm the IOC.
    Returns list of confirming source names.
    """
    confirmed_by = []
    ioc_lower    = ioc.lower().replace(".exe", "").replace(":", " ")

    for source, text in targeted.items():
        if not text or "[TIMEOUT]" in text or "[ERROR]" in text:
            continue
        if any(tok.lower() in text.lower() for tok in ioc_lower.split() if len(tok) > 3):
            confirmed_by.append(source)

    return confirmed_by


DERIVED_EVIDENCE_SOURCES = {
    "memory:timeline_hints",
    "memory:triage_summary",
}

COMMON_LOLBINS = {
    "rundll32.exe",
    "mshta.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe",
    "powershell.exe",
    "cmd.exe",
}


def _canonical_source(source: str) -> str:
    if source in ("memory:strings_ioc", "memory:yara_scan"):
        return "memory:triage"
    return source


def _has_suspicious_lolbin_context(ioc: str, raw_evidence: dict) -> bool:
    ioc_l = ioc.lower()
    if ioc_l not in COMMON_LOLBINS:
        return True
    corpus = "\n".join(
        raw_evidence.get(k, "")
        for k in ("vol3:cmdline", "vol2:cmdscan", "vol2:consoles", "memory:strings_ioc")
        if raw_evidence.get(k)
    ).lower()
    suspicious_markers = (
        "-enc", "-encodedcommand", "frombase64string", "downloadstring",
        "javascript:", "vbscript:", "mshtml", "scrobj.dll", "/i:http",
        ".sct", ".hta", ".dll,", ",#", "\\appdata\\", "\\temp\\", "http://", "https://",
    )
    return ioc_l in corpus and any(marker in corpus for marker in suspicious_markers)


def run_evidence_agent(state: InvestigationState) -> InvestigationState:
    """
    LangGraph node: for each hypothesis, gather targeted evidence
    and update verified_sources list.
    """
    print("\n==================================================", flush=True)
    print("  PHASE 3 - TARGETED EVIDENCE AGENT", flush=True)
    print("==================================================", flush=True)

    filepath     = state["filepath"]
    raw_evidence = state.get("raw_evidence", {})
    hypotheses   = state.get("hypotheses", [])
    os_type      = state.get("os_type", "windows")

    updated = []
    reasoning = state.get("reasoning_log", [])
    import time as _time

    for h in hypotheses:
        print(f"\n  Evidence for {h['id']}: {h['ioc']}", flush=True)
        targeted = gather_targeted_evidence(filepath, h, raw_evidence, os_type)
        confirmed_by = check_evidence_confirms(targeted, h["ioc"])

        # Also check existing raw evidence
        for plugin, text in raw_evidence.items():
            if plugin in DERIVED_EVIDENCE_SOURCES:
                continue
            if plugin in ("vol2:shimcache", "vol3:shimcachemem") and not _has_suspicious_lolbin_context(h["ioc"], raw_evidence):
                continue
            if text and h["ioc"].lower().replace(".exe", "") in text.lower():
                source = _canonical_source(plugin)
                if source not in confirmed_by:
                    confirmed_by.append(source)

        confirmed_by = sorted({_canonical_source(source) for source in confirmed_by})

        h["verified_sources"] = list(set(confirmed_by))
        print(f"    Confirmed by {len(confirmed_by)} sources: {confirmed_by[:5]}", flush=True)

        # Reasoning trace
        reasoning.append({
            "agent": "Evidence",
            "action": f"Targeted re-query for {h['id']} ({h['ioc']})",
            "rationale": f"Phase={h.get('attack_phase','?')} - ran PID-specific malfind/dlllist/cmdline "
                         f"+ IP-filtered netscan/netstat to independently verify this IOC "
                         f"without relying on initial bulk collection alone",
            "result": f"{len(confirmed_by)} independent sources confirmed: "
                      f"{', '.join(confirmed_by[:5])}{'...' if len(confirmed_by) > 5 else ''}",
            "timestamp": _time.time(),
        })

        updated.append(h)

    return {**state, "hypotheses": updated, "reasoning_log": reasoning}
