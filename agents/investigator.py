"""
PHANTOM DFIR - Investigator Agent v3.0
Analyzes raw evidence and proposes forensic hypotheses.
Each hypothesis has a specific, falsifiable claim + supporting raw evidence.

v3.0 - Dynamic Legitimacy Engine integration
     - Behavioral false positive filtering (path, parent, network, memory)
     - No hardcoded process name allowlists
v2.0 - Dynamic IOC extraction (no hardcoded IPs/ports)
     - SSH target extraction from PuTTY/ssh cmdlines
     - Better Linux static rules
     - Robust JSON control char stripping
"""
import json
import re
import uuid
from langchain_core.prompts import PromptTemplate

from state import InvestigationState
from config import OLLAMA_BASE_URL, OLLAMA_MODEL, TIMEOUT_LLM
from correlation.mitre import map_hypothesis_to_mitre
from tools.legitimacy_engine import filter_legitimate_hypotheses
from tools.llm_provider import create_llm
from tools.skills_loader import load_skills_for_phase

llm = create_llm(temperature=0.1)

INVESTIGATOR_PROMPT = PromptTemplate.from_template("""
You are a senior DFIR analyst analyzing a {os_type} memory dump.
Identify SPECIFIC, FALSIFIABLE hypotheses backed by exact evidence.
{skill_context}

CRITICAL RULES FOR THE 'ioc' FIELD:
- ioc MUST be a SHORT specific value: a filename, an IP address, or a PID number
- GOOD ioc examples: "ruby.exe", "172.16.4.10", "subject_srv.exe", "putty.exe", "3204"
- BAD ioc examples: "PID: 3204, Parent: services.exe", "File path: C:\\\\windows\\\\", "Multiple instances"
- If the ioc is longer than 30 characters or contains spaces, it is WRONG - shorten it to the key artifact

=== RAW EVIDENCE (first 4000 chars) ===
{evidence_summary}
=======================================

Return a JSON array. Each entry:
{{
  "id": "H001",
  "claim": "Specific falsifiable claim with concrete details from the evidence",
  "ioc": "SHORT specific value - filename/IP/PID only, NO descriptions",
  "attack_phase": "Persistence|Execution|C2|LateralMovement|CredentialAccess|PrivEsc|DefenseEvasion",
  "raw_evidence_quote": "Exact line from the evidence above",
  "requires_verification": ["specific plugin re-runs needed"]
}}

Key things to look for:
- ruby.exe or rubyw.exe spawned by services.exe -> Metasploit, ioc="ruby.exe"
- Suspicious executables NOT in System32 -> malware service, ioc="<filename>.exe"
- connections to unusual ports (8080, 4444, 1337) -> C2, ioc="<actual_IP>"
- putty.exe / plink.exe multiple times -> lateral movement, ioc="putty.exe"
- bash reverse shells (/dev/tcp, mkfifo | nc) -> C2, ioc="/dev/tcp"
- wget with --proxy or --header Cookie -> stealth download, ioc="wget"
- LD_PRELOAD in environment -> userland rootkit, ioc="LD_PRELOAD"
- syscall table hooks -> kernel rootkit, ioc="sys_call_table"

Return ONLY valid JSON array, no other text.
""")



def _display_claim_for_console(h: dict) -> str:
    """Keep console wording neutral for uncorroborated LLM/string leads."""
    claim = (h.get("claim") or "").strip()
    ioc = (h.get("ioc") or "unknown").strip()
    lower = claim.lower()
    if (
        "potentially compromised" in lower
        or "being targeted" in lower
        or "suggesting" in lower
        or "attacks" in lower
        or "detected" in lower
    ):
        return f"Uncorroborated lead requiring analyst review: {ioc}"
    return claim

def _truncate_evidence(raw_evidence: dict, max_chars: int = 12000) -> str:
    """Build a focused evidence summary, prioritising high-value plugins."""
    priority = [
        "memory:triage_summary", "memory:strings_ioc", "memory:yara_scan",
        "memory:timeline_hints",
        "vol3:pslist", "vol3:pstree", "vol3:netscan", "vol3:shimcachemem",
        "vol3:svcscan", "vol3:cmdline", "vol3:malfind", "vol3:svcdiff",
        "vol3:psxview", "vol2:svcscan", "vol2:netscan",
        # Linux priority
        "vol3:linux_pslist", "vol3:linux_bash", "vol3:linux_sockstat",
        "vol3:linux_malfind", "vol3:linux_check_syscall", "vol3:linux_hidden_modules",
        "vol3:linux_process_spoof", "vol3:linux_ebpf", "vol3:linux_netfilter",
    ]
    lines = []
    total = 0

    for key in priority:
        if key in raw_evidence and raw_evidence[key]:
            snippet = raw_evidence[key][:2000]
            entry   = f"\n--- {key} ---\n{snippet}\n"
            if total + len(entry) > max_chars:
                break
            lines.append(entry)
            total += len(entry)

    for key, val in raw_evidence.items():
        if key not in priority and val and total < max_chars:
            snippet = val[:500]
            entry   = f"\n--- {key} ---\n{snippet}\n"
            lines.append(entry)
            total += len(entry)

    return "".join(lines)


def _is_valid_ioc(ioc: str) -> bool:
    if not ioc or len(ioc) > 40:
        return False
    # Reject common system process names - they match everywhere and produce noise
    SYSTEM_PROCESS_EXCLUSIONS = {
        "svchost.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "dwm.exe", "explorer.exe", "conhost.exe",
        "dllhost.exe", "taskhostw.exe", "spoolsv.exe", "ctfmon.exe",
        "sihost.exe", "fontdrvhost.exe", "wmiprvse.exe", "msdtc.exe",
        "searchui.exe", "runtimebroker.exe", "system", "registry",
        "audiodg.exe", "lsaiso.exe", "wudfhost.exe", "searchindexer.exe",
        "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe",
    }
    if ioc.lower() in SYSTEM_PROCESS_EXCLUSIONS:
        return False
    has_dot     = "." in ioc
    is_ip       = bool(re.match(r"\d{1,3}\.\d{1,3}", ioc))
    is_filename = has_dot and " " not in ioc
    is_short    = len(ioc) <= 20 and " " not in ioc
    return is_ip or is_filename or is_short


def _strip_control_chars(text: str) -> str:
    """
    Aggressively strip ALL control characters that break JSON parsing.
    Volatility outputs tabs (\t), form feeds (\x0c), carriage returns (\r), etc.
    """
    # Replace tabs with spaces
    text = text.replace('\t', ' ')
    text = text.replace('\r', ' ')
    text = text.replace('\n\n\n', '\n')  # collapse excess newlines
    # Strip ALL other control chars except newline (0x0a)
    text = re.sub(r'[\x00-\x09\x0b-\x1f\x7f]', '', text)
    return text


# -- Benign Binary Path Detection ----------------------------------------------

# Known-legitimate paths for ruby.exe - these are NOT Metasploit
BENIGN_RUBY_PATHS = [
    "puppet labs",
    "chef",
    "opscode",
    "rubyinstaller",
    "railsinstaller",
    "bitnami",
    "ruby\\bin\\ruby",      # standard Ruby SDK install
]


def _is_benign_ruby(raw_evidence: dict) -> bool:
    """
    Check if all ruby.exe instances come from known-legitimate install paths.
    If ANY ruby.exe is from an unknown/suspicious path, return False.
    """
    path_sources = ["vol3:pstree", "vol3:cmdline", "vol3:dlllist", "vol3:svcscan", "vol3:svclist"]
    ruby_lines = []
    for plugin in path_sources:
        text = raw_evidence.get(plugin, "")
        for line in text.splitlines():
            if "ruby" in line.lower():
                ruby_lines.append(line)

    if not ruby_lines:
        return False  # Can't determine - treat as suspicious

    for line in ruby_lines:
        ll = line.lower()
        if any(benign in ll for benign in BENIGN_RUBY_PATHS):
            continue  # This line is from a benign path
        # Check if line contains a path at all - if it does and isn't benign, suspicious
        if "\\" in line or "/" in line:
            # Has a path but not in benign list - suspicious ruby
            return False
    return True  # All ruby instances are from benign paths


def _extract_raw_evidence_line(raw_evidence: dict, ioc: str,
                                priority_plugins: list = None) -> str:
    """
    Extract the most informative raw evidence line for an IOC.
    Searches priority plugins first, falls back to any plugin.
    Returns the longest matching line (up to 200 chars) for maximum context.
    """
    if priority_plugins is None:
        priority_plugins = [
            "vol3:pstree", "vol3:svcscan", "vol3:svclist",
            "vol3:cmdline", "vol3:netscan", "vol3:netstat",
            "vol3:pslist", "vol3:sessions",
        ]

    ioc_lower = ioc.lower().replace(".exe", "")
    best_line = ""
    best_score = 0

    def _score_line(line: str) -> int:
        """Score a line by how informative it is for forensic context."""
        s = 0
        ll = line.lower()
        if ioc_lower in ll:
            s += 10
        # Bonus for containing paths (shows binary location)
        if "\\" in line or "/" in line:
            s += 5
        # Bonus for containing timestamps
        if re.search(r'20\d{2}-\d{2}-\d{2}', line):
            s += 3
        # Bonus for containing PIDs
        if re.search(r'\b\d{3,5}\b', line):
            s += 2
        # Bonus for containing network info
        if re.search(r'\d+\.\d+\.\d+\.\d+', line):
            s += 3
        # Bonus for line length (more context)
        s += min(len(line) // 50, 3)
        return s

    for plugin in priority_plugins:
        text = raw_evidence.get(plugin, "")
        if not text:
            continue
        for line in text.splitlines():
            if ioc_lower in line.lower():
                score = _score_line(line)
                if score > best_score:
                    best_score = score
                    best_line = line.strip()[:200]

    # Fallback: search all evidence if nothing found in priority plugins
    if not best_line:
        for plugin, text in raw_evidence.items():
            if not text or plugin in priority_plugins:
                continue
            for line in text.splitlines():
                if ioc_lower in line.lower():
                    score = _score_line(line)
                    if score > best_score:
                        best_score = score
                        best_line = line.strip()[:200]

    return best_line or ioc  # Final fallback: just the IOC name


# -- Dynamic IOC Extraction Helpers --------------------------------------------

def _extract_c2_connections(raw_evidence: dict) -> list:
    """
    Dynamically extract suspicious C2 connections from netscan/netstat.
    Finds non-standard ports with external connections - no hardcoded IPs.
    """
    c2_candidates = []
    SUSPICIOUS_PORTS = {"8080", "4444", "1337", "9090", "8443", "1234", "5555",
                        "6666", "7777", "8888", "9999", "31337"}
    BENIGN_PORTS = {"80", "443", "53", "22", "88", "135", "139", "389", "445",
                    "636", "3268", "3269", "5985", "5986"}

    for plugin in ["vol3:netscan", "vol3:netstat", "vol2:netscan"]:
        text = raw_evidence.get(plugin, "")
        if not text:
            continue
        for line in text.splitlines():
            if "ESTABLISHED" not in line and "CLOSE_WAIT" not in line:
                continue
            # Find IP:port patterns
            ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)', line)
            for ip, port in ip_matches:
                if ip in ("0.0.0.0", "127.0.0.1", "*"):
                    continue
                if port in SUSPICIOUS_PORTS or (port not in BENIGN_PORTS and int(port) > 1024):
                    # Check it's not local (source) address - look for it as remote
                    if port in SUSPICIOUS_PORTS:
                        c2_candidates.append({
                            "ip": ip, "port": port,
                            "line": line.strip()[:200],
                            "plugin": plugin,
                        })
    # Deduplicate by IP:port
    seen = set()
    unique = []
    for c in c2_candidates:
        key = f"{c['ip']}:{c['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def _extract_ssh_targets(raw_evidence: dict) -> list:
    """
    Extract SSH/PuTTY connection targets from cmdline and pstree output.
    Finds hostnames (@hostname) and IP:port combinations.
    """
    targets = []
    for plugin in ["vol3:pstree", "vol3:cmdline"]:
        text = raw_evidence.get(plugin, "")
        if not text:
            continue
        for line in text.splitlines():
            line_lower = line.lower()
            if "putty" not in line_lower and "plink" not in line_lower and "ssh" not in line_lower:
                continue
            # Extract @hostname targets (PuTTY style)
            at_hosts = re.findall(r'@([\w\-\.]+)', line)
            for host in at_hosts:
                if host not in ("", "localhost") and len(host) > 2:
                    targets.append({"target": host, "line": line.strip()[:200]})
            # Extract IP:port targets
            ip_targets = re.findall(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:\s]+(\d+))?',
                line)
            for ip, port in ip_targets:
                port = port or "22"
                targets.append({"target": f"{ip}:{port}", "line": line.strip()[:200]})
    # Deduplicate
    seen = set()
    unique = []
    for t in targets:
        if t["target"] not in seen:
            seen.add(t["target"])
            unique.append(t)
    return unique


def _extract_suspicious_services(raw_evidence: dict) -> list:
    """
    Dynamically find services running from non-System32 paths.
    Deduplicates by exe name to avoid duplicate hypotheses.
    """
    suspicious = []
    seen_exes = set()

    # Windows has a small number of legitimate service binaries outside
    # System32. Treat these as explainable findings, not compromise.
    known_legitimate_service_paths = {
        "trustedinstaller.exe": [
            r"c:\windows\servicing\trustedinstaller.exe",
        ],
    }

    for plugin in ["vol3:svcscan", "vol3:svclist", "vol2:svcscan"]:
        text = raw_evidence.get(plugin, "")
        if not text:
            continue
        for line in text.splitlines():
            ll = line.lower()
            # Running service with path NOT in System32
            if ("c:\\windows\\" in ll and "system32" not in ll and
                    "syswow64" not in ll and ".exe" in ll):
                # Extract the executable name
                m = re.search(r'([\w\-]+\.exe)', line, re.I)
                if m:
                    exe_name = m.group(1)
                    if exe_name.lower() not in seen_exes:
                        seen_exes.add(exe_name.lower())
                        exe_key = exe_name.lower()
                        is_known_legit = any(
                            legit_path in ll
                            for legit_path in known_legitimate_service_paths.get(exe_key, [])
                        )
                        suspicious.append({
                            "exe": exe_name,
                            "line": line.strip()[:200],
                            "plugin": plugin,
                            "known_legitimate": is_known_legit,
                        })
    return suspicious


def _choose_triage_ioc(category: str, line: str) -> str:
    """Return a short, stable IOC from a memory-triage line."""
    lower = line.lower()
    if category == "network_indicator":
        m = re.search(r"https?://[^\s\"'<>]{4,}|(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}", line, re.I)
        if m:
            return m.group(0).rstrip(".,);]")[:40]
    keyword_map = {
        "credential_theft": ["mimikatz", "sekurlsa", "lsass.dmp", "procdump", "comsvcs.dll", "wdigest"],
        "c2_framework": ["meterpreter", "metasploit", "cobalt strike", "beacon", "sliver", "havoc"],
        "powershell_stager": ["powershell", "pwsh", "-encodedcommand", "frombase64string"],
        "suspicious_shell": ["cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe"],
        "linux_reverse_shell": ["/dev/tcp", "/dev/udp", "mkfifo", "nc -e", "bash -i"],
    }
    for keyword in keyword_map.get(category, []):
        if keyword in lower:
            return keyword
    m = re.search(r"([A-Za-z0-9_.:/-]{3,40})", line)
    return m.group(1) if m else category


def _extract_memory_triage_hypotheses(raw_evidence: dict) -> list:
    """Convert bounded memory-triage hits into falsifiable baseline hypotheses."""
    hypotheses = []
    seen = set()
    category_map = {
        "credential_theft": (
            "CredentialAccess",
            "Credential-theft indicator found in raw memory triage",
            ["vol2:hashdump", "vol2:lsadump", "vol3:malfind"],
        ),
        "c2_framework": (
            "C2",
            "Known C2 framework indicator found in raw memory triage",
            ["vol3:netscan", "vol2:netscan", "vol3:malfind"],
        ),
        "powershell_stager": (
            "Execution",
            "PowerShell encoded-command or stager pattern found in raw memory triage",
            ["vol3:cmdline", "vol2:cmdscan", "vol2:consoles"],
        ),
        "suspicious_shell": (
            "Execution",
            "Suspicious Windows script or shell execution pattern found in raw memory triage",
            ["vol3:cmdline", "vol3:pstree", "vol2:cmdscan"],
        ),
        "linux_reverse_shell": (
            "C2",
            "Linux reverse-shell indicator found in raw memory triage",
            ["vol3:linux_bash", "vol3:linux_sockstat", "vol3:linux_psaux"],
        ),
    }

    for line in raw_evidence.get("memory:strings_ioc", "").splitlines():
        m = re.match(r"\[([a-z_]+)\]\s+(.*)", line)
        if not m:
            continue
        category, body = m.group(1), m.group(2)
        if category not in category_map:
            continue
        phase, claim, verify = category_map[category]
        ioc = _choose_triage_ioc(category, body)
        key = (category, ioc.lower())
        if key in seen or not _is_valid_ioc(ioc):
            continue
        seen.add(key)
        hypotheses.append({
            "id": "H-MEM",
            "claim": f"{claim}: {ioc}",
            "ioc": ioc,
            "attack_phase": phase,
            "raw_evidence_quote": line[:180],
            "requires_verification": verify,
        })
        if len(hypotheses) >= 8:
            break

    for line in raw_evidence.get("memory:yara_scan", "").splitlines():
        if not line or line.startswith("["):
            continue
        rule = line.split()[0]
        if not rule.startswith("PHANTOM_Memory_"):
            continue
        ioc = rule.replace("PHANTOM_Memory_", "").lower()[:40]
        key = ("yara", ioc)
        if key in seen or not _is_valid_ioc(ioc):
            continue
        seen.add(key)
        phase = "C2" if "c2" in ioc or "reverse" in ioc else "Execution"
        if "mimikatz" in ioc:
            phase = "CredentialAccess"
        hypotheses.append({
            "id": "H-YARA",
            "claim": f"Embedded PHANTOM YARA memory rule matched: {rule}",
            "ioc": ioc,
            "attack_phase": phase,
            "raw_evidence_quote": line[:180],
            "requires_verification": ["vol3:malfind", "vol3:pslist", "vol3:netscan"],
        })
        if len(hypotheses) >= 10:
            break
    return hypotheses


def run_investigator(state: InvestigationState) -> InvestigationState:
    print("\n==================================================", flush=True)
    print("  PHASE 2 - INVESTIGATOR AGENT", flush=True)
    print("==================================================", flush=True)

    raw_evidence     = state.get("raw_evidence", {})
    os_type          = state.get("os_type", "unknown")
    evidence_summary = _truncate_evidence(raw_evidence, max_chars=4000)

    # -- Always run static fallback first (guaranteed baseline) ----------------
    static_hyps = _static_fallback(raw_evidence, os_type)
    print(f"  Static analysis: {len(static_hyps)} baseline hypotheses", flush=True)

    # -- Try LLM for additional hypotheses -------------------------------------
    llm_hyps = []
    skill_context = load_skills_for_phase("investigator")
    if skill_context:
        print(f"  Skills loaded: {len(skill_context)} chars of expert context", flush=True)
    if llm is not None:
        print(f"  Sending {len(evidence_summary)} chars to {OLLAMA_MODEL}...", flush=True)
        try:
            chain  = INVESTIGATOR_PROMPT | llm
            output = chain.invoke({
                "evidence_summary": evidence_summary,
                "os_type": os_type.upper(),
                "skill_context": skill_context,
            })
            start  = output.find("[")
            end    = output.rfind("]") + 1
            if start != -1 and end > 0:
                raw_json = output[start:end]
                # ROBUST control character stripping
                raw_json = _strip_control_chars(raw_json)
                raw_list = json.loads(raw_json)
                # Validate IOC fields
                for h in raw_list:
                    ioc = h.get("ioc", "")
                    if _is_valid_ioc(ioc):
                        llm_hyps.append(h)
                    else:
                        print(f"  [!] Rejected vague LLM IOC: '{ioc[:50]}'", flush=True)
                print(f"  LLM contributed {len(llm_hyps)} valid hypotheses", flush=True)
        except json.JSONDecodeError as e:
            print(f"  [!] JSON parse error: {e}", flush=True)
            print(f"  [!] Raw LLM output preview: {output[:200] if 'output' in locals() else 'N/A'}", flush=True)
        except Exception as e:
            print(f"  [!] LLM error: {e}", flush=True)

    # -- Merge: static is baseline, LLM adds NEW IOCs only --------------------
    # Deduplicate static hypotheses by IOC first
    seen_static_iocs = set()
    deduped_static = []
    for h in static_hyps:
        ioc_key = h["ioc"].lower()
        if ioc_key not in seen_static_iocs:
            seen_static_iocs.add(ioc_key)
            deduped_static.append(h)
        else:
            print(f"  [dedup] Skipping duplicate static hypothesis for '{h['ioc']}'", flush=True)

    static_iocs = {h["ioc"].lower() for h in deduped_static}
    merged = list(deduped_static)
    for h in llm_hyps:
        if h.get("ioc", "").lower() not in static_iocs:
            merged.append(h)

    # -- Normalise all hypotheses ----------------------------------------------
    hypotheses = []
    for i, h in enumerate(merged):
        h["id"]                = f"H{i+1:03d}"
        h["verified_sources"]  = []
        h["skeptic_challenges"]= []
        h["confidence"]        = "UNVERIFIED"
        h["mitre_ids"]         = map_hypothesis_to_mitre(h)
        hypotheses.append(h)
        print(f"  -> {h['id']}: {_display_claim_for_console(h)[:80]}", flush=True)

    print(f"\n  {len(hypotheses)} total hypotheses (before legitimacy filtering).", flush=True)

    # -- Legitimacy Engine: filter out behaviorally-legitimate processes ----
    threshold = state.get("legitimacy_threshold", 70)
    print(f"\n  Running legitimacy engine (threshold={threshold})...", flush=True)
    kept, filtered = filter_legitimate_hypotheses(
        hypotheses, raw_evidence, os_type, threshold=threshold
    )

    if filtered:
        print(f"  Legitimacy engine cleared {len(filtered)} legitimate process(es).", flush=True)
    print(f"  {len(kept)} hypotheses remain for investigation.", flush=True)

    # -- Reasoning Trace ---------------------------------------------------
    import time as _time
    reasoning = state.get("reasoning_log", [])
    reasoning.append({
        "agent": "Investigator",
        "action": "Static rule-based analysis",
        "rationale": f"Scanned {len(raw_evidence)} plugin outputs with {os_type}-specific rules "
                     f"(process legitimacy, C2 ports, SSH targets, benign Ruby detection). "
                     f"Static rules are deterministic and hallucination-free.",
        "result": f"{len(deduped_static)} baseline hypotheses from static rules",
        "timestamp": _time.time(),
    })
    if llm is not None:
        reasoning.append({
            "agent": "Investigator",
            "action": "LLM hypothesis generation",
            "rationale": f"Sent {len(evidence_summary)} chars of priority-ordered evidence to "
                         f"{OLLAMA_MODEL} for adversarial hypothesis generation. LLM finds "
                         f"patterns humans encode as rules miss.",
            "result": f"{len(llm_hyps)} LLM hypotheses (after IOC validation), "
                      f"merged to {len(kept) + len(filtered)} total",
            "timestamp": _time.time(),
        })
    if filtered:
        reasoning.append({
            "agent": "Investigator",
            "action": "Legitimacy filtering",
            "rationale": f"Behavioral legitimacy engine scored each hypothesis on path, "
                         f"parent-child relationship, network behavior, and memory anomalies. "
                         f"Threshold={threshold}/100.",
            "result": f"{len(filtered)} cleared (legitimate), {len(kept)} kept for investigation",
            "timestamp": _time.time(),
        })

    # Track cleared processes from legitimacy engine without duplicating them
    # across skeptic/self-correction rounds.
    existing_fp = state.get("false_positives_detected", [])
    merged_fp = []
    seen_fp = set()
    for item in existing_fp + filtered:
        key = (item.get("ioc") or item.get("claim") or "").lower().strip()
        if not key or key in seen_fp:
            continue
        seen_fp.add(key)
        merged_fp.append(item)

    return {
        **state,
        "hypotheses": kept,
        "false_positives_detected": merged_fp,
        "cleared_findings": filtered,
        "reasoning_log": reasoning,
    }


def _static_fallback(raw_evidence: dict, os_type: str) -> list:
    """
    Rule-based fallback - never returns empty.
    v2.0: Dynamic IOC extraction - no hardcoded IPs/ports.
    """
    hypotheses = _extract_memory_triage_hypotheses(raw_evidence)
    combined = "\n".join(v for v in raw_evidence.values() if v)

    # ===============================================================
    # WINDOWS STATIC RULES
    # ===============================================================
    if os_type == "windows":

        # -- Dynamic: Suspicious services NOT in System32 ----------
        for svc in _extract_suspicious_services(raw_evidence):
            exe = svc["exe"]
            if svc.get("known_legitimate"):
                hypotheses.append({
                    "id":    f"S-SVC",
                    "claim": f"{exe} service path verified benign",
                    "ioc":   exe,
                    "attack_phase": "Persistence",
                    "raw_evidence_quote": svc["line"][:100],
                    "requires_verification": ["vol3:svcscan", "vol3:pslist", f"vol3:malfind {exe} pid"],
                })
            else:
                hypotheses.append({
                    "id":    f"S-SVC",
                    "claim": f"{exe} running as a Windows service from non-System32 path - suspicious",
                    "ioc":   exe,
                    "attack_phase": "Persistence",
                    "raw_evidence_quote": svc["line"][:100],
                    "requires_verification": ["vol3:svcscan", "vol3:pslist", f"vol3:malfind {exe} pid"],
                })

        # -- Metasploit indicators ---------------------------------
        if "ruby.exe" in combined or "rubyw.exe" in combined:
            if _is_benign_ruby(raw_evidence):
                # Known-benign Ruby (Puppet, Chef, etc.) - downgrade to LOW
                ruby_quote = _extract_raw_evidence_line(raw_evidence, "ruby.exe")
                hypotheses.append({
                    "id":    "H-RUBY",
                    "claim": "ruby.exe from legitimate software (Puppet/Chef) running as service - likely benign",
                    "ioc":   "ruby.exe",
                    "attack_phase": "Execution",
                    "raw_evidence_quote": ruby_quote,
                    "requires_verification": ["vol3:pslist", "vol3:cmdline", "vol3:pstree"],
                })
            else:
                ruby_quote = _extract_raw_evidence_line(raw_evidence, "ruby.exe")
                hypotheses.append({
                    "id":    "H-RUBY",
                    "claim": "ruby.exe / rubyw.exe spawned by services.exe - Metasploit Framework C2 agent",
                    "ioc":   "ruby.exe",
                    "attack_phase": "C2",
                    "raw_evidence_quote": ruby_quote,
                    "requires_verification": ["vol3:pslist", "vol3:netscan", "vol3:malfind ruby pid"],
                })

        # -- Dynamic: C2 connections (no hardcoded IPs) ------------
        for c2 in _extract_c2_connections(raw_evidence):
            ioc_str = f"{c2['ip']}:{c2['port']}"
            hypotheses.append({
                "id":    f"H-C2",
                "claim": f"Network connection to {ioc_str} - potential C2 channel (port {c2['port']})",
                "ioc":   ioc_str,
                "attack_phase": "C2",
                "raw_evidence_quote": c2["line"][:100],
                "requires_verification": ["vol3:netscan", "vol2:netscan"],
            })

        # -- PuTTY / SSH lateral movement --------------------------
        if "putty" in combined.lower():
            putty_quote = _extract_raw_evidence_line(raw_evidence, "putty.exe")
            hypotheses.append({
                "id":    "H-PUTTY",
                "claim": "Multiple putty.exe instances - lateral SSH movement from compromised host",
                "ioc":   "putty.exe",
                "attack_phase": "LateralMovement",
                "raw_evidence_quote": putty_quote,
                "requires_verification": ["vol3:pslist", "vol3:netscan"],
            })

        # -- Dynamic: SSH targets from PuTTY/plink cmdlines --------
        ssh_targets = _extract_ssh_targets(raw_evidence)
        if ssh_targets:
            target_list = ", ".join(t["target"] for t in ssh_targets[:5])
            hypotheses.append({
                "id":    "H-SSH-NET",
                "claim": f"SSH lateral movement targets identified: {target_list}",
                "ioc":   ssh_targets[0]["target"],
                "attack_phase": "LateralMovement",
                "raw_evidence_quote": ssh_targets[0]["line"][:100],
                "requires_verification": ["vol3:netscan", "vol3:cmdline"],
            })

        # -- Credential tools --------------------------------------
        if "mimikatz" in combined.lower() or "writeprocessmemory" in combined.lower():
            cred_ioc = "mimikatz" if "mimikatz" in combined.lower() else "writeprocessmemory"
            cred_quote = _extract_raw_evidence_line(raw_evidence, cred_ioc)
            hypotheses.append({
                "id":    "H-CRED",
                "claim": "Mimikatz strings / process injection APIs found in memory - credential theft possible",
                "ioc":   "mimikatz",
                "attack_phase": "CredentialAccess",
                "raw_evidence_quote": cred_quote,
                "requires_verification": ["vol2:hashdump", "vol2:lsadump"],
            })

    # ===============================================================
    # LINUX STATIC RULES
    # ===============================================================
    elif os_type == "linux":
        # Bash reverse shells
        if "/dev/tcp" in combined or "mkfifo" in combined:
            revshell_ioc = "/dev/tcp" if "/dev/tcp" in combined else "mkfifo"
            revshell_quote = _extract_raw_evidence_line(raw_evidence, revshell_ioc)
            hypotheses.append({
                "id":    "L001",
                "claim": "Bash reverse shell via /dev/tcp or mkfifo+nc - C2 connection established",
                "ioc":   "/dev/tcp",
                "attack_phase": "C2",
                "raw_evidence_quote": revshell_quote,
                "requires_verification": ["vol3:linux_bash", "vol3:linux_sockstat"],
            })

        # Stealth download patterns
        if "wget" in combined and ("--proxy" in combined or "--header" in combined or "Cookie:" in combined):
            wget_quote = _extract_raw_evidence_line(raw_evidence, "wget")
            hypotheses.append({
                "id":    "L002",
                "claim": "wget with --proxy/--header/Cookie - stealth download with anti-forensics",
                "ioc":   "wget",
                "attack_phase": "Execution",
                "raw_evidence_quote": wget_quote,
                "requires_verification": ["vol3:linux_bash", "vol3:linux_psaux"],
            })

        # LD_PRELOAD userland rootkit
        if "LD_PRELOAD" in combined and "/tmp" not in combined:
            ldpreload_quote = _extract_raw_evidence_line(raw_evidence, "LD_PRELOAD")
            hypotheses.append({
                "id":    "L003",
                "claim": "LD_PRELOAD in environment - userland rootkit library injection",
                "ioc":   "LD_PRELOAD",
                "attack_phase": "DefenseEvasion",
                "raw_evidence_quote": ldpreload_quote,
                "requires_verification": ["vol3:linux_envars", "vol3:linux_library_list"],
            })

        # Syscall table hooks (kernel rootkit)
        if "sys_call_table" in combined.lower() or "hooked" in combined.lower():
            syscall_ioc = "sys_call_table" if "sys_call_table" in combined.lower() else "hooked"
            syscall_quote = _extract_raw_evidence_line(raw_evidence, syscall_ioc)
            hypotheses.append({
                "id":    "L004",
                "claim": "Syscall table hooks detected - kernel-level rootkit compromise",
                "ioc":   "sys_call_table",
                "attack_phase": "DefenseEvasion",
                "raw_evidence_quote": syscall_quote,
                "requires_verification": ["vol3:linux_check_syscall", "vol3:linux_hidden_modules"],
            })

        # Hidden kernel modules
        if "hidden" in combined.lower() and "module" in combined.lower():
            hidden_quote = _extract_raw_evidence_line(raw_evidence, "hidden")
            hypotheses.append({
                "id":    "L005",
                "claim": "Hidden kernel modules (not in lsmod) - LKM rootkit detected",
                "ioc":   "hidden_module",
                "attack_phase": "DefenseEvasion",
                "raw_evidence_quote": hidden_quote,
                "requires_verification": ["vol3:linux_hidden_modules", "vol3:linux_modxview"],
            })

        # Process name spoofing
        if "comm" in combined and "cmdline" in combined and "mismatch" in combined.lower():
            hypotheses.append({
                "id":    "L006",
                "claim": "Process name spoofing detected - comm/cmdline/exe mismatch",
                "ioc":   "process_spoof",
                "attack_phase": "DefenseEvasion",
                "raw_evidence_quote": "comm cmdline mismatch",
                "requires_verification": ["vol3:linux_process_spoof", "vol3:linux_psaux"],
            })

        # eBPF programs (modern fileless rootkits)
        if "ebpf" in combined.lower() or "bpf" in combined.lower():
            hypotheses.append({
                "id":    "L007",
                "claim": "eBPF programs found in memory - modern fileless rootkit or monitoring tool",
                "ioc":   "ebpf",
                "attack_phase": "DefenseEvasion",
                "raw_evidence_quote": "ebpf",
                "requires_verification": ["vol3:linux_ebpf", "vol3:linux_check_ftrace"],
            })

        # Bash history cleared / anti-forensics
        if "HISTFILE=/dev/null" in combined or "history -c" in combined or "unset HISTFILE" in combined:
            hypotheses.append({
                "id":    "L008",
                "claim": "Bash history clearing detected - anti-forensics in bash commands",
                "ioc":   "HISTFILE=/dev/null",
                "attack_phase": "DefenseEvasion",
                "raw_evidence_quote": "HISTFILE=/dev/null",
                "requires_verification": ["vol3:linux_bash", "vol3:linux_envars"],
            })

        # SSH connections from unusual processes
        if "ssh" in combined.lower() and ("172." in combined or "192.168" in combined or "10." in combined):
            ssh_quote = _extract_raw_evidence_line(raw_evidence, "ssh")
            hypotheses.append({
                "id":    "L009",
                "claim": "SSH connections to internal network - lateral movement or C2 tunneling",
                "ioc":   "ssh",
                "attack_phase": "LateralMovement",
                "raw_evidence_quote": ssh_quote,
                "requires_verification": ["vol3:linux_sockstat", "vol3:linux_bash"],
            })

        # Files executed from /tmp or /dev/shm (fileless staging)
        if ("/tmp/" in combined or "/dev/shm" in combined) and ("exec" in combined.lower() or "chmod +x" in combined):
            hypotheses.append({
                "id":    "L010",
                "claim": "Execution from /tmp or /dev/shm - fileless malware staging area",
                "ioc":   "/tmp",
                "attack_phase": "Execution",
                "raw_evidence_quote": "/tmp/",
                "requires_verification": ["vol3:linux_bash", "vol3:linux_lsof"],
            })

    return hypotheses
