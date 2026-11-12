"""
PHANTOM DFIR - ATT&CK technique condition engine.

This module deliberately avoids "keyword = technique" reporting. It separates
ATT&CK output into:

- confirmed: PHANTOM MEDIUM/CRITICAL findings mapped to ATT&CK
- supported: technique-specific conditions seen in two or more evidence families
- leads: single-family weak signals that should guide review, not drive verdicts
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from correlation.mitre import CONTEXT_TECHNIQUE_MAP, IOC_TECHNIQUE_MAP, build_kill_chain


TECHNIQUE_NAMES = {}
for _mapping in (IOC_TECHNIQUE_MAP, CONTEXT_TECHNIQUE_MAP):
    for _, (_tid, _name) in _mapping.items():
        TECHNIQUE_NAMES.setdefault(_tid, _name)

CHAIN_ORDER = [
    "T1566", "T1078", "T1059", "T1218", "T1053",
    "T1543", "T1547", "T1055", "T1134", "T1562",
    "T1036", "T1003", "T1057", "T1049", "T1021",
    "T1047", "T1071", "T1095", "T1567", "T1005",
]


@dataclass(frozen=True)
class TechniqueRule:
    technique_id: str
    technique_name: str
    tactic: str
    families: tuple[str, ...]
    required: tuple[str, ...]
    suspicious: tuple[str, ...]
    rationale: str


RULES = [
    TechniqueRule(
        "T1059.001",
        "PowerShell",
        "Execution",
        ("command", "process", "memory"),
        ("powershell",),
        ("-enc", "-encodedcommand", "frombase64string", "downloadstring", "invoke-expression", " iex "),
        "PowerShell is mapped only when suspicious execution flags or stager strings are present.",
    ),
    TechniqueRule(
        "T1218.005",
        "Mshta",
        "Defense Evasion",
        ("command", "process", "memory"),
        ("mshta",),
        ("http://", "https://", "javascript:", "vbscript:", ".hta", "\\appdata\\", "\\temp\\"),
        "Mshta requires script/URL/user-writable-path context.",
    ),
    TechniqueRule(
        "T1218.010",
        "Regsvr32",
        "Defense Evasion",
        ("command", "process", "memory"),
        ("regsvr32",),
        ("scrobj.dll", "/i:", "http://", "https://", ".sct", "\\appdata\\", "\\temp\\"),
        "Regsvr32 requires Squiblydoo-style or user-writable scriptlet context.",
    ),
    TechniqueRule(
        "T1218.011",
        "Rundll32",
        "Defense Evasion",
        ("command", "process", "memory"),
        ("rundll32",),
        ("javascript:", "mshtml", "http://", "https://", ".dll,", ",#", "\\appdata\\", "\\temp\\"),
        "Rundll32 requires DLL export, script proxy, URL, ordinal, or user-writable-path context.",
    ),
    TechniqueRule(
        "T1003.001",
        "LSASS Memory",
        "Credential Access",
        ("credential", "command", "memory"),
        ("mimikatz", "sekurlsa", "lsass", "wdigest"),
        ("logonpasswords", "sekurlsa", "lsass.dmp", "procdump", "comsvcs.dll", "minidump"),
        "Credential dumping requires tool, LSASS dump, or secret-extraction context.",
    ),
    TechniqueRule(
        "T1055",
        "Process Injection",
        "Defense Evasion",
        ("memory_anomaly", "process", "memory"),
        ("malfind", "virtualalloc", "writeprocessmemory", "createremotethread"),
        ("vad", "private", "execute", "reflective", "injection", "hollow"),
        "Process injection requires memory anomaly or injection API context.",
    ),
    TechniqueRule(
        "T1095",
        "Non-Application Layer Protocol",
        "Command and Control",
        ("network", "memory", "process"),
        ("meterpreter", "metasploit", "beacon", "cobalt", ":4444", ":1337"),
        ("established", "tcp", "reverse", "payload", "session"),
        "C2 protocol mapping requires C2 framework or unusual-port evidence with network/process context.",
    ),
    TechniqueRule(
        "T1021.004",
        "SSH",
        "Lateral Movement",
        ("command", "network", "process"),
        ("putty", "plink", "ssh "),
        ("@", ":22", "password", "privatekey", "identityfile"),
        "SSH lateral movement requires client command or target/session context.",
    ),
]


FAMILY_KEYS = {
    "process": (
        "vol3:pslist", "vol3:pstree", "vol3:psscan", "vol3:cmdline",
        "vol3:linux_pslist", "vol3:linux_pstree", "vol3:linux_psaux",
    ),
    "command": (
        "vol3:cmdline", "vol3:cmdscan", "vol3:consoles", "vol2:cmdscan",
        "vol2:consoles", "vol3:linux_bash", "vol3:linux_psaux",
    ),
    "network": (
        "vol3:netscan", "vol3:netstat", "vol2:netscan",
        "vol3:linux_sockstat", "vol3:linux_sockscan",
    ),
    "memory": (
        "memory:strings_ioc", "memory:yara_scan",
    ),
    "memory_anomaly": (
        "vol3:malfind", "vol3:linux_malfind", "memory:yara_scan",
    ),
    "credential": (
        "vol2:hashdump", "vol2:cachedump", "vol2:lsadump", "memory:strings_ioc",
    ),
    "service": (
        "vol3:svcscan", "vol3:svclist", "vol2:svcscan",
    ),
}


def _chain_rank(technique_id: str) -> int:
    base = technique_id.split(".")[0]
    return CHAIN_ORDER.index(base) if base in CHAIN_ORDER else 99


def _family_text(raw_evidence: dict, family: str) -> tuple[str, list[str]]:
    keys = FAMILY_KEYS.get(family, ())
    used = []
    chunks = []
    for key in keys:
        text = raw_evidence.get(key, "")
        if text and "[ERROR]" not in text and "[TIMEOUT]" not in text:
            used.append(key)
            chunks.append(text)
    return "\n".join(chunks).lower(), used


def _matches_rule(raw_evidence: dict, rule: TechniqueRule) -> dict | None:
    matched_families = []
    matched_sources = []
    matched_required = set()
    matched_suspicious = set()

    for family in rule.families:
        text, sources = _family_text(raw_evidence, family)
        if not text:
            continue
        family_required = {term for term in rule.required if term.lower() in text}
        family_suspicious = {term for term in rule.suspicious if term.lower() in text}
        if family_required or family_suspicious:
            matched_sources.extend(sources)
        if family_required:
            matched_required.update(family_required)
        if family_suspicious:
            matched_suspicious.update(family_suspicious)
        if family_required and family_suspicious:
            matched_families.append(family)

    if not matched_required:
        return None

    if len(matched_families) >= 2:
        tier = "supported"
        confidence = "MEDIUM"
    elif matched_suspicious:
        tier = "lead"
        confidence = "LOW"
    else:
        return None

    return {
        "technique_id": rule.technique_id,
        "technique_name": rule.technique_name,
        "tactic": rule.tactic,
        "tier": tier,
        "confidence": confidence,
        "matched_required": sorted(matched_required),
        "matched_suspicious": sorted(matched_suspicious),
        "source_plugins": sorted(set(matched_sources)),
        "rationale": rule.rationale,
    }


def _confirmed_from_findings(findings: list[dict]) -> list[dict]:
    confirmed = {}
    for finding in findings:
        if finding.get("confidence") not in ("CRITICAL", "MEDIUM"):
            continue
        for tid in finding.get("mitre_ids", []):
            confirmed.setdefault(tid, {
                "technique_id": tid,
                "technique_name": TECHNIQUE_NAMES.get(tid, "Mapped from confirmed finding"),
                "tactic": finding.get("attack_phase", "Unknown"),
                "tier": "confirmed",
                "confidence": finding.get("confidence"),
                "matched_required": [finding.get("ioc", "")],
                "matched_suspicious": [],
                "source_plugins": finding.get("verified_sources", []),
                "rationale": "Mapped from a PHANTOM MEDIUM/CRITICAL finding after skeptic review.",
            })
    return list(confirmed.values())


def evaluate_attack_rules(raw_evidence: dict, findings: list[dict]) -> dict:
    """Return ATT&CK technique review split into confirmed, supported, and leads."""
    confirmed = _confirmed_from_findings(findings)
    confirmed_ids = {item["technique_id"] for item in confirmed}

    supported = []
    leads = []
    for rule in RULES:
        item = _matches_rule(raw_evidence, rule)
        if not item or item["technique_id"] in confirmed_ids:
            continue
        if item["tier"] == "supported":
            supported.append(item)
        else:
            leads.append(item)

    def sort_items(items: list[dict]) -> list[dict]:
        return sorted(items, key=lambda item: (_chain_rank(item["technique_id"]), item["technique_id"]))

    confirmed = sort_items(confirmed)
    supported = sort_items(supported)
    leads = sort_items(leads)
    return {
        "confirmed": confirmed,
        "supported": supported,
        "leads": leads,
        "kill_chain": build_kill_chain(confirmed),
    }
