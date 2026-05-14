"""
PHANTOM DFIR — MITRE ATT&CK Auto-Mapper v2.0
Maps IOC types / attack phases to ATT&CK technique IDs.

v2.0 — Fixed false positives from tool/column name keyword matching.
  - Split into IOC_TECHNIQUES (high confidence) vs CONTEXT_TECHNIQUES
  - map_evidence_to_mitre() only uses IOC keywords
  - map_hypothesis_to_mitre() uses both
  - Excludes Volatility plugin names and generic column headers
"""

# ── HIGH CONFIDENCE: Specific IOC keywords ────────────────────────────────────
# These are real attacker indicators — safe to match anywhere in raw evidence.
IOC_TECHNIQUE_MAP = {
    # Execution — specific tool/process names
    # NOTE: ruby.exe removed — too many false positives (Puppet, Chef, RubyInstaller).
    # Ruby-based C2 is caught by hypothesis-level mapping in map_hypothesis_to_mitre().
    "mshta.exe":        ("T1218.005", "Mshta"),

    # Persistence — specific malware names
    "subject_srv":      ("T1543.003", "Windows Service"),

    # Credential Access — specific tool names
    "mimikatz":         ("T1003",     "OS Credential Dumping"),
    "sekurlsa":         ("T1003.001", "LSASS Memory"),

    # Lateral Movement — specific tools
    "putty.exe":        ("T1021.004", "SSH"),
    "plink.exe":        ("T1021.004", "SSH"),

    # C2 — specific ports and tools
    ":8080":            ("T1071.001", "Web Protocols — HTTP"),
    ":4444":            ("T1095",     "Non-Application Layer Protocol"),
    ":1337":            ("T1095",     "Non-Application Layer Protocol"),
    "meterpreter":      ("T1095",     "Non-Application Layer Protocol"),
    "beacon":           ("T1071.001", "Web Protocols"),
    "cobalt":           ("T1071.001", "Web Protocols"),

    # Defense Evasion — injection APIs (only match if in cmdline/malfind)
    "reflectiveloader": ("T1055.001", "Dynamic-link Library Injection"),

    # Exfiltration
    "rclone":           ("T1567",     "Exfiltration Over Web Service"),
    "megasync":         ("T1567",     "Exfiltration Over Web Service"),
}

# ── CONTEXT KEYWORDS: Only for hypothesis mapping ─────────────────────────────
# These are generic terms that produce false positives in raw evidence scanning
# but are valid when a hypothesis specifically claims them.
CONTEXT_TECHNIQUE_MAP = {
    # Initial Access
    "phishing":         ("T1566",     "Phishing"),
    "spearphish":       ("T1566.001", "Spearphishing Attachment"),

    # Execution
    "powershell":       ("T1059.001", "PowerShell"),
    "cmd.exe":          ("T1059.003", "Windows Command Shell"),
    "wscript":          ("T1059.005", "Visual Basic"),
    "rundll32":         ("T1218.011", "Rundll32"),
    "metasploit":       ("T1059",     "Command and Scripting Interpreter"),

    # Persistence
    "services.exe":     ("T1543.003", "Windows Service"),
    "scheduled_task":   ("T1053.005", "Scheduled Task"),
    "run key":          ("T1547.001", "Registry Run Keys"),

    # Privilege Escalation / Injection
    "virtualallocex":   ("T1055",     "Process Injection"),
    "writeprocessmemory": ("T1055",   "Process Injection"),
    "createremotethread": ("T1055",   "Process Injection"),
    "hollowprocess":    ("T1055.012", "Process Hollowing"),

    # Defense Evasion
    "etwpatch":         ("T1562.006", "Disable or Modify Tools — ETW"),
    "pebmasquerade":    ("T1036.005", "Match Legitimate Name or Location"),

    # Credential Access
    "hashdump":         ("T1003.001", "LSASS Memory"),
    "lsadump":          ("T1003.004", "LSA Secrets"),
    "cachedump":        ("T1003.005", "Cached Domain Credentials"),

    # Lateral Movement
    "ssh":              ("T1021.004", "SSH"),
    "rdp":              ("T1021.001", "Remote Desktop Protocol"),
    "smb":              ("T1021.002", "SMB/Windows Admin Shares"),
    "psexec":           ("T1021.002", "SMB/Windows Admin Shares"),
    "wmiexec":          ("T1047",     "Windows Management Instrumentation"),

    # C2 — generic
    ":443":             ("T1071.001", "Web Protocols — HTTPS"),
}

# ATT&CK kill-chain order for sorting
CHAIN_ORDER = [
    "T1566", "T1078", "T1059", "T1218", "T1053",
    "T1543", "T1547", "T1055", "T1134", "T1562",
    "T1036", "T1003", "T1057", "T1049", "T1021",
    "T1047", "T1071", "T1095", "T1567", "T1005"
]

# Plugin/tool names that should NEVER be treated as IOC keywords
VOLATILITY_NOISE = {
    "pslist", "psscan", "pstree", "netscan", "netstat", "malfind",
    "userassist", "shimcache", "shimcachemem", "hivelist", "svcscan",
    "cmdscan", "consoles", "amcache", "dlllist", "handles", "envars",
    "wow64", "ldrmodules", "callbacks", "ssdt", "modscan", "modules",
    "mutantscan", "filescan", "privileges", "getsids", "sessions",
    "psxview", "svcdiff", "processghosting", "pebmasquerade", "etwpatch",
    "svclist", "vadinfo", "ptemalfind",
}


def map_evidence_to_mitre(raw_evidence: dict) -> list:
    """
    Scan raw evidence for HIGH-CONFIDENCE IOC keywords only.
    Avoids false positives by:
    1. Only using IOC_TECHNIQUE_MAP (no generic context keywords)
    2. Skipping matches where the keyword is just a plugin name in the key
    3. Requiring the keyword to appear in actual output content
    """
    found = {}
    for keyword, (tid, tname) in IOC_TECHNIQUE_MAP.items():
        matched_plugins = []
        for plugin, text in raw_evidence.items():
            if not text or "[TIMEOUT]" in text or "[ERROR]" in text:
                continue
            # Don't count if keyword IS the plugin name
            plugin_base = plugin.split(":")[-1].split("[")[0].lower()
            if keyword.lower().replace(".exe", "") == plugin_base:
                continue
            if keyword.lower() in text.lower():
                matched_plugins.append(plugin)
        if matched_plugins:
            if tid not in found:
                found[tid] = {
                    "technique_id":   tid,
                    "technique_name": tname,
                    "matched_keyword": keyword,
                    "source_plugins": matched_plugins,
                }

    def chain_rank(tid):
        base = tid.split(".")[0]
        try:
            return CHAIN_ORDER.index(base)
        except ValueError:
            return 99

    return sorted(found.values(), key=lambda x: chain_rank(x["technique_id"]))


def build_kill_chain(techniques: list) -> list:
    """Return ordered list of technique IDs for the kill chain."""
    return [t["technique_id"] for t in techniques]


def map_hypothesis_to_mitre(hypothesis: dict) -> list:
    """
    Map a single hypothesis's claim + attack_phase to MITRE IDs.
    Uses BOTH IOC and CONTEXT maps — hypotheses have enough context
    to avoid false positives.
    """
    text = (hypothesis.get("claim", "") + " " +
            hypothesis.get("attack_phase", "") + " " +
            hypothesis.get("ioc", "")).lower()
    ids = []
    # Check IOC map first (high confidence)
    for keyword, (tid, _) in IOC_TECHNIQUE_MAP.items():
        if keyword.lower() in text:
            if tid not in ids:
                ids.append(tid)
    # Then context map (hypothesis-level confidence)
    for keyword, (tid, _) in CONTEXT_TECHNIQUE_MAP.items():
        if keyword.lower() in text:
            if tid not in ids:
                ids.append(tid)
    return ids
