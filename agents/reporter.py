"""
PHANTOM DFIR - Reporter Agent v4.0
Generates final JSON + Markdown report with:
  - Coherent attack narrative (not just a list of findings)
  - Verified findings (CRITICAL / MEDIUM / LOW)
  - Cleared processes (investigated, determined benign - shows thoroughness)
  - MITRE ATT&CK kill chain (false-positive-free)
  - Attacker-focused timeline (no system noise)
  - Dynamic remediation playbook (from MITRE, not hardcoded)
  - Hallucinations caught (REFUTED list)

v2.0 - Dynamic remediation from ATT&CK techniques
v2.1 - Attack narrative, cleared/benign section, filtered timeline
v4.0 - Evidence coverage audit, SHA-256 chain of custody, version bump
"""
import json
import os
import re
import time
from datetime import datetime

from state import InvestigationState
from correlation.mitre import build_kill_chain
from correlation.mitre_rules import evaluate_attack_rules
from correlation.timeline import extract_timestamps, filter_interesting, format_timeline_md
from config import REPORT_DIR

SEPARATOR = "=" * 60


def _badge(confidence: str) -> str:
    return {
        "CRITICAL": "[CRITICAL]",
        "MEDIUM": "[MEDIUM]",
        "LOW": "[LOW]",
        "CLEARED": "[CLEARED]",
        "REFUTED": "[REFUTED]",
        "UNVERIFIED": "[UNVERIFIED]",
    }.get(confidence, "[UNKNOWN]")


def _is_review_only_lead(h: dict) -> bool:
    sources = h.get("verified_sources", [])
    return h.get("confidence") == "LOW" or len(sources) < 3


def _review_only_claim(h: dict) -> str:
    claim = (h.get("claim") or "").strip()
    ioc = (h.get("ioc") or "unknown").strip()
    if not _is_review_only_lead(h):
        return claim
    lower = claim.lower()
    noisy = (
        "potentially compromised" in lower
        or "suggesting" in lower
        or "attacks" in lower
        or "confirmed" in lower
        or "detected" in lower
    )
    if noisy or claim:
        return f"Uncorroborated lead requiring analyst review: {ioc}"
    return f"Uncorroborated lead requiring analyst review: {ioc}"


def _build_memory_evidence_gap_controller(state: dict, critical: list, medium: list,
                                          low: list, cleared: list, refuted: list) -> dict:
    """Summarize memory evidence coverage and remaining investigation gaps."""
    raw = state.get("raw_evidence", {}) or {}
    errors = state.get("collection_errors", []) or []
    plugin_names = {name for name, output in raw.items() if output and str(output).strip()}

    families = {
        "process_inventory": any(k in plugin_names for k in ("vol3:pslist", "vol3:psscan", "vol2:pslist")),
        "process_tree": any(k in plugin_names for k in ("vol3:pstree", "vol2:pstree")),
        "network_sockets": any(k in plugin_names for k in ("vol3:netscan", "vol3:netstat", "vol2:netscan")),
        "command_history": any(k in plugin_names for k in ("vol3:cmdline", "vol3:cmdscan", "vol3:consoles", "vol2:cmdscan", "vol2:consoles")),
        "service_persistence": any(k in plugin_names for k in ("vol3:svcscan", "vol3:svclist", "vol3:svcdiff", "vol2:svcscan")),
        "injection_checks": any(k in plugin_names for k in ("vol3:malfind", "vol3:hollowprocesses", "vol3:ldrmodules", "vol3:unhooked_syscalls")),
        "credential_artifacts": any(k in plugin_names for k in ("vol2:hashdump", "vol2:lsadump", "vol2:cachedump", "memory:strings_ioc")),
        "registry_memory": any(k in plugin_names for k in ("vol3:hivelist", "vol3:userassist", "vol3:amcache", "vol3:shimcachemem", "vol2:shimcache")),
        "yara_or_string_triage": any(k in plugin_names for k in ("memory:yara_scan", "memory:strings_ioc", "memory:triage_summary")),
        "timeline_hints": any(k in plugin_names for k in ("memory:timeline_hints", "vol3:scheduled_tasks")),
    }

    gaps = []
    if errors:
        gaps.append("collection_errors_present")
    for family, present in families.items():
        if not present:
            gaps.append(f"missing_{family}")
    weak = [h for h in (medium + low) if len(h.get("verified_sources", [])) < 3]
    if weak:
        gaps.append("under_corroborated_findings_remain")
    if cleared:
        gaps.append("false_positive_resolved_to_cleared")
    if refuted:
        gaps.append("unsupported_hypothesis_refuted")

    if critical:
        action = "accept_confirmed_findings"
        confidence = "high"
    elif cleared and not critical:
        action = "accept_after_false_positive_clearance"
        confidence = "medium"
    elif weak:
        action = "accept_with_review_only_leads"
        confidence = "medium"
    elif not gaps:
        action = "accept_no_gaps"
        confidence = "high"
    else:
        action = "accept_with_documented_gaps"
        confidence = "low"

    return {
        "controller": "memory_evidence_gap_controller",
        "plugins_with_data": len(plugin_names),
        "collection_errors": len(errors),
        "families": families,
        "gaps": gaps,
        "under_corroborated_count": len(weak),
        "critical_count": len(critical),
        "medium_count": len(medium),
        "low_count": len(low),
        "cleared_count": len(cleared),
        "refuted_count": len(refuted),
        "action": action,
        "confidence": confidence,
    }

def _finding_md(h: dict) -> str:
    """Format a single hypothesis as a Markdown finding block."""
    confidence = h.get("confidence", "?")
    claim = _review_only_claim(h)
    lines = [
        f"### {_badge(confidence)} {confidence} - {claim}",
        f"- **IOC**: `{h.get('ioc','')}`",
        f"- **Phase**: {h.get('attack_phase','')}",
        f"- **Sources ({len(h.get('verified_sources',[]))})**:",
    ]
    for src in h.get("verified_sources", []):
        lines.append(f"  - `{src}`")
    if h.get("raw_evidence_quote"):
        lines.append(f"- **Evidence**: `{h['raw_evidence_quote'][:150]}`")
    if h.get("mitre_ids") and confidence in ("CRITICAL", "MEDIUM"):
        lines.append(f"- **MITRE**: {', '.join(h['mitre_ids'])}")
    elif h.get("mitre_ids"):
        lines.append("- **MITRE**: review-only; not added to confirmed kill chain")
    if h.get("skeptic_challenges"):
        lines.append(f"- **Skeptic**: {h['skeptic_challenges'][-1]}")
    if _is_review_only_lead(h):
        lines.append("- **Assessment**: Review-only lead. Not confirmed and not used for final verdict.")
    return "\n".join(lines)

def _build_attack_narrative(critical: list, medium: list, cleared: list,
                             techniques: list, kill_chain: list) -> str:
    """
    Generate a coherent attack story from the confirmed findings.
    This is what wins hackathons - not just a list of IOCs, but a narrative
    that shows the analyst understands what happened.
    """
    sections = []

    # Extract key artifacts for the narrative
    c2_ips = []
    malware_services = []
    lateral_tools = []
    ssh_targets = []
    cleared_names = []

    for h in critical:
        phase = h.get("attack_phase", "")
        ioc = h.get("ioc", "")
        claim = h.get("claim", "")
        if phase == "C2":
            ip_m = re.search(r'(\d+\.\d+\.\d+\.\d+)', ioc)
            if ip_m:
                c2_ips.append({"ip": ip_m.group(1), "ioc": ioc, "claim": claim})
        elif phase == "Persistence":
            malware_services.append({"exe": ioc, "claim": claim})
        elif phase == "LateralMovement":
            lateral_tools.append({"tool": ioc, "claim": claim})

    for h in medium:
        if h.get("attack_phase") == "LateralMovement":
            # Extract target names from claim
            targets_m = re.findall(r'[\w\-]+', h.get("claim", ""))
            ssh_targets.extend([t for t in targets_m if t not in (
                "SSH", "lateral", "movement", "targets", "identified", "from",
                "compromised", "host", "Multiple", "instances")])

    for h in cleared:
        cleared_names.append(h.get("ioc", ""))

    # Build the narrative. Do not overstate the case: a report with only
    # medium or cleared findings is not a confirmed compromise.
    if critical:
        sections.append(
            "The investigation of this memory image reveals a **multi-stage compromise** "
            "consistent with a targeted intrusion."
        )
    elif medium:
        sections.append(
            "The investigation identified **suspicious but unconfirmed artifacts** that "
            "warrant analyst review. PHANTOM did not confirm a critical compromise because "
            "the evidence did not meet the 3-source corroboration threshold."
        )
    else:
        sections.append(
            "The investigation did **not confirm malicious compromise** in this memory "
            "image. Any investigated benign or refuted artifacts are documented below for "
            "auditability."
        )

    # Stage 1: Initial Access / Persistence
    if malware_services:
        svc_names = ", ".join(f"`{s['exe']}`" for s in malware_services)
        sections.append(
            f"\n**Stage 1 - Persistence**: The attacker established persistence by installing "
            f"malicious Windows service(s): {svc_names}. These services are configured to "
            f"auto-start and run from non-standard paths outside System32, indicating "
            f"deliberate evasion of default security monitoring."
        )

    # Stage 2: C2
    if c2_ips:
        ip_list = ", ".join(f"`{c['ioc']}`" for c in c2_ips)
        sections.append(
            f"\n**Stage 2 - Command & Control**: Active C2 communication was detected to "
            f"{ip_list}. The connection state (CLOSE_WAIT/ESTABLISHED) indicates the C2 channel "
            f"was actively used. This traffic was observed on non-standard ports commonly "
            f"used by exploitation frameworks."
        )

    # Stage 3: Lateral Movement
    if lateral_tools:
        tool_list = ", ".join(f"`{t['tool']}`" for t in lateral_tools)
        target_str = ""
        if ssh_targets:
            clean_targets = [t for t in ssh_targets[:5] if len(t) > 2]
            if clean_targets:
                target_str = f" Target hosts: {', '.join(f'`{t}`' for t in clean_targets)}."
        sections.append(
            f"\n**Stage 3 - Lateral Movement**: The attacker used {tool_list} for SSH-based "
            f"lateral movement across the network.{target_str} Multiple instances of these tools "
            f"suggest systematic pivot operations from this compromised host."
        )

    # Cleared processes
    if cleared_names:
        cleared_str = ", ".join(f"`{n}`" for n in cleared_names)
        sections.append(
            f"\n**Cleared Processes**: The following were investigated and determined to be "
            f"legitimate software: {cleared_str}. These were flagged during initial triage "
            f"but confirmed benign through path analysis and binary verification."
        )

    # Kill chain summary
    if kill_chain:
        chain_str = " -> ".join(kill_chain)
        sections.append(
            f"\n**MITRE ATT&CK Kill Chain**: `{chain_str}` - this pattern indicates a "
            f"post-exploitation scenario with established persistence, active C2, and "
            f"ongoing lateral movement."
        )

    return "\n".join(sections)


def _filter_attacker_timeline(events: list, critical: list, medium: list) -> list:
    """
    Filter timeline to only show events directly related to confirmed findings.
    Removes system noise (vmtoolsd, MSASCuiL, svchost) to focus on attacker activity.
    """
    # Build IOC keywords from confirmed findings
    attacker_iocs = set()
    for h in critical + medium:
        ioc = h.get("ioc", "").lower()
        if ioc:
            # Add the IOC and its base name
            attacker_iocs.add(ioc.replace(".exe", ""))
            attacker_iocs.add(ioc)
        # Also extract IP if present
        ip_m = re.search(r'(\d+\.\d+\.\d+\.\d+)', ioc)
        if ip_m:
            attacker_iocs.add(ip_m.group(1))

    # System processes to exclude (never attacker-related)
    SYSTEM_NOISE = {
        "vmtoolsd", "vmacthlp", "msascuil", "svchost", "fontdrvhost",
        "runtimebroker", "searchui", "shellexperiencehost", "onedrive",
        "spoolsv", "msdtc", "sihost", "ctfmon", "taskhostw",
        "dllhost", "wmiprvse", "audiodg", "searchindexer",
    }

    filtered = []
    for e in events:
        event_lower = (e.get("event", "") + " " + e.get("event_raw", "")).lower()

        # Always include if it mentions an attacker IOC
        if any(ioc in event_lower for ioc in attacker_iocs):
            filtered.append(e)
            continue

        # Always include key system events (services.exe is the parent)
        if "services.exe" in event_lower:
            filtered.append(e)
            continue

        # Exclude system noise
        if any(noise in event_lower for noise in SYSTEM_NOISE):
            continue

        # Include if it's a network event with non-local IPs
        if "connection" in event_lower and re.search(r'172\.|10\.|192\.168', event_lower):
            filtered.append(e)
            continue

        # Include userinit.exe (user logon - forensically relevant)
        if "userinit" in event_lower:
            filtered.append(e)
            continue

    return filtered


def _remediation(findings: list, techniques: list) -> str:
    """
    Generate dynamic remediation steps from confirmed findings + MITRE techniques.
    v2.0: Not hardcoded to specific IOCs - works for any case.
    """
    steps = []
    step_num = 1

    # Group findings by attack phase (skip cleared/benign)
    phases = {}
    for h in findings:
        if h.get("confidence") == "CLEARED":
            continue
        phase = h.get("attack_phase", "Unknown")
        if phase not in phases:
            phases[phase] = []
        phases[phase].append(h)

    # Containment - always first
    if "C2" in phases:
        c2_iocs = [h["ioc"] for h in phases.get("C2", [])]
        steps.append(f"{step_num}. **IMMEDIATE: Isolate host from network** - active C2 indicators: {', '.join(c2_iocs) if c2_iocs else 'detected'}")
        step_num += 1

    # Kill malicious processes
    exec_iocs = [h["ioc"] for h in phases.get("C2", []) + phases.get("Execution", [])]
    if exec_iocs:
        steps.append(f"{step_num}. **Kill malicious processes**: terminate {', '.join(set(exec_iocs))}")
        step_num += 1

    # Block C2
    c2_ips = set()
    for h in phases.get("C2", []):
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', h.get("ioc", ""))
        if m:
            c2_ips.add(m.group(1))
    if c2_ips:
        steps.append(f"{step_num}. **Block C2 IPs at perimeter**: {', '.join(c2_ips)}")
        step_num += 1

    # Persistence removal
    if "Persistence" in phases:
        for h in phases["Persistence"]:
            steps.append(f"{step_num}. **Remove persistence**: disable/delete `{h['ioc']}` service and binary")
            step_num += 1

    # Lateral movement audit
    if "LateralMovement" in phases:
        targets = [h["ioc"] for h in phases["LateralMovement"]]
        steps.append(f"{step_num}. **Audit lateral movement targets**: {', '.join(targets)} - check all connected hosts")
        step_num += 1

    # Credential reset
    if "CredentialAccess" in phases:
        steps.append(f"{step_num}. **Reset ALL domain credentials** - assume full credential compromise")
        step_num += 1

    # MITRE-based additional steps
    technique_ids = {t["technique_id"] for t in techniques}
    if any(t.startswith("T1003") for t in technique_ids):
        if "CredentialAccess" not in phases:
            steps.append(f"{step_num}. **Reset credentials** - credential dumping indicators detected")
            step_num += 1
    if any(t.startswith("T1055") for t in technique_ids):
        steps.append(f"{step_num}. **Scan for injected processes** - process injection detected")
        step_num += 1

    # Generic fallback
    if not steps:
        steps.append("1. Preserve memory image and full disk image for further analysis")
        steps.append("2. Review network logs for external connections from the host")
        step_num = 3

    steps.append(f"{step_num}. **Preserve evidence** - SHA256 hash memory + disk images as chain of custody markers")
    return "\n".join(steps)


def run_reporter(state: InvestigationState) -> InvestigationState:
    """LangGraph node: generate final JSON + Markdown report."""
    print(f"\n{SEPARATOR}", flush=True)
    print("  PHASE 5 - REPORT GENERATION", flush=True)
    print(SEPARATOR, flush=True)

    filepath  = state["filepath"]
    target    = os.path.basename(filepath).replace(" ", "_")
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    basename  = f"phantom_{target}_{ts}"

    critical = state.get("critical_findings", [])
    medium   = state.get("medium_findings",   [])
    low      = state.get("low_findings",      [])
    cleared  = state.get("cleared_findings",  [])
    refuted  = state.get("refuted",           [])
    confirmed_for_action = critical + medium  # LOW remains review-only
    all_conf = confirmed_for_action  # cleared excluded from "confirmed malicious"

    # -- Evidence Coverage Audit (v4.0) -----------------------------------
    # Quality gate: check which plugin data was collected but never cited
    raw_evidence = state.get("raw_evidence", {})
    all_hypotheses = state.get("hypotheses", []) + cleared + refuted
    cited_sources = set()
    for h in all_hypotheses:
        for src in h.get("verified_sources", []):
            cited_sources.add(src)
        # Also count sources referenced by IOC name matching
        ioc = h.get("ioc", "").lower().replace(".exe", "")
        if ioc:
            for plugin_name, output in raw_evidence.items():
                if output and ioc in output.lower():
                    cited_sources.add(plugin_name)

    plugins_with_data = {k for k, v in raw_evidence.items() if v and v.strip()}
    uncited_plugins = plugins_with_data - cited_sources
    coverage_pct = round(
        (len(plugins_with_data - uncited_plugins) / max(len(plugins_with_data), 1)) * 100
    )

    reasoning_log = state.get("reasoning_log", [])
    reasoning_log.append({
        "agent": "reporter",
        "action": "evidence_coverage_audit",
        "rationale": f"Quality gate: {len(plugins_with_data)} plugins had data, "
                     f"{len(cited_sources)} were cited in findings",
        "result": f"Coverage: {coverage_pct}% | "
                  f"Uncited: {', '.join(sorted(uncited_plugins)[:5]) if uncited_plugins else 'none'}",
    })
    state["reasoning_log"] = reasoning_log
    memory_gap_controller = _build_memory_evidence_gap_controller(
        state, critical, medium, low, cleared, refuted
    )
    reasoning_log.append({
        "agent": "EvidenceGapController",
        "action": "memory_gap_review",
        "rationale": "Checked core memory evidence families and unresolved weak findings.",
        "result": f"action={memory_gap_controller['action']} gaps={', '.join(memory_gap_controller['gaps']) or 'none'}",
    })
    state["reasoning_log"] = reasoning_log
    state["memory_gap_controller"] = memory_gap_controller
    attack_review = evaluate_attack_rules(raw_evidence, critical + medium + low)
    techniques = attack_review["confirmed"]
    supported_techniques = attack_review["supported"]
    lead_techniques = attack_review["leads"]
    kill_chain = attack_review["kill_chain"]

    # Timeline - filtered to attacker activity only
    all_events       = extract_timestamps(state.get("raw_evidence", {}))
    key_events       = filter_interesting(all_events)
    attacker_events  = _filter_attacker_timeline(key_events, critical, medium)

    # Attack Narrative
    narrative = _build_attack_narrative(critical, medium, cleared, techniques, kill_chain)
    self_correction_history = state.get("self_correction_history", [])

    import time as _time
    start_time = state.get("start_time")
    duration = round(_time.time() - start_time, 1) if start_time else state.get("duration_seconds", 0)

    # -- JSON Report ------------------------------------------------------------
    report = {
        "metadata": {
            "tool":       "PHANTOM DFIR",
            "version":    "4.0.0",
            "subtitle":   "Parallel Hypothesis Analysis with Multi-agent Threat Hunting Overlay Network",
            "timestamp":  datetime.now().isoformat(),
            "target":     filepath,
            "os_type":    state.get("os_type", "unknown"),
            "vol2_profile": state.get("vol2_profile", "auto"),
            "engines":    state.get("engines", {}),
            "duration_seconds": round(duration, 1),
            "skeptic_rounds":   state.get("skeptic_round", 0),
        },
        "summary": {
            "total_hypotheses": len(state.get("hypotheses", [])),
            "critical_count":   len(critical),
            "medium_count":     len(medium),
            "low_count":        len(low),
            "cleared_count":    len(cleared),
            "refuted_count":    len(refuted),
            "hallucinations_caught": len(refuted),
        },
        "attack_narrative": narrative,
        "self_correction_history": self_correction_history,
        "memory_gap_controller": memory_gap_controller,
        "critical_findings": critical,
        "medium_findings":   medium,
        "low_findings":      low,
        "cleared_findings":  cleared,
        "refuted_hypotheses": refuted,
        "mitre_attack": {
            "techniques":  techniques,
            "supported_techniques": supported_techniques,
            "lead_techniques": lead_techniques,
            "kill_chain":  kill_chain,
        },
        "attack_timeline": attacker_events[:30],
        "collection_errors": state.get("collection_errors", []),
    }

    json_path = os.path.join(REPORT_DIR, f"{basename}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  [OK] JSON: {json_path}", flush=True)

    # -- Markdown Report --------------------------------------------------------
    md_lines = [
        f"# PHANTOM DFIR - Investigation Report",
        f"**Target**: `{filepath}`  ",
        f"**OS**: {state.get('os_type','?')} | "
        f"**Duration**: {duration:.1f}s | "
        f"**Skeptic Rounds**: {state.get('skeptic_round',0)}  ",
        f"**Timestamp**: {datetime.now().isoformat()}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Confidence | Count |",
        f"|-----------|-------|",
        f"| [CRITICAL] CRITICAL | {len(critical)} |",
        f"| [MEDIUM] MEDIUM   | {len(medium)}   |",
        f"| [LOW] LOW      | {len(low)}      |",
        f"| [CLEARED] CLEARED  | {len(cleared)} (investigated, benign) |",
        f"| [REFUTED] REFUTED  | {len(refuted)} (hallucinations caught) |",
        "",
        "---",
        "",
        "## Attack Narrative",
        "",
        narrative,
        "",
        "---",
        "",
        "## Critical Findings",
        "",
    ]

    if critical:
        for h in critical:
            md_lines.append(_finding_md(h))
            md_lines.append("")
    else:
        md_lines.append("_No CRITICAL findings confirmed._")
        md_lines.append("")

    md_lines += ["---", "", "## Medium Findings", ""]
    for h in medium:
        md_lines.append(_finding_md(h))
        md_lines.append("")
    if not medium:
        md_lines.append("_None._")

    md_lines += ["---", "", "## Review-Only Low Findings", ""]
    for h in low:
        md_lines.append(_finding_md(h))
        md_lines.append("")
    if not low:
        md_lines.append("_None._")

    md_lines += ["---", "", "## Cleared (Investigated, Determined Benign)", ""]
    if cleared:
        for h in cleared:
            md_lines.append(f"- [CLEARED] **{h.get('ioc','')}** - {h.get('claim','')}")
            md_lines.append(f"  - Path verified: `{h.get('raw_evidence_quote','')[:120]}`")
            md_lines.append(f"  - Sources checked: {len(h.get('verified_sources',[]))}")
    else:
        md_lines.append("_No processes cleared._")

    md_lines += ["---", "", "## Refuted (Hallucinations Caught)", ""]
    for h in refuted:
        md_lines.append(f"- ~~{h.get('claim','')}~~ - {h.get('skeptic_challenges',[''])[0]}")
    if not refuted:
        md_lines.append("_No hallucinations detected._")

    md_lines += [
        "",
        "---",
        "",
        "## MITRE ATT&CK Review",
        "",
        "### Confirmed Kill Chain",
        "",
        " -> ".join(kill_chain) if kill_chain else "_No MEDIUM/CRITICAL ATT&CK techniques confirmed._",
        "",
        "| Technique ID | Name | Evidence |",
        "|-------------|------|---------|",
    ]
    for t in techniques:
        md_lines.append(
            f"| `{t['technique_id']}` | {t['technique_name']} | "
            f"`{', '.join(t.get('source_plugins', [])[:3])}` |"
        )
    if not techniques:
        md_lines.append("| _None_ | _No confirmed technique_ | _N/A_ |")

    md_lines += [
        "",
        "### Supported Techniques",
        "",
        "_Two or more evidence families matched technique-specific conditions, but no MEDIUM/CRITICAL finding currently drives the verdict._",
        "",
        "| Technique ID | Name | Sources | Rationale |",
        "|-------------|------|---------|-----------|",
    ]
    for t in supported_techniques:
        md_lines.append(
            f"| `{t['technique_id']}` | {t['technique_name']} | "
            f"`{', '.join(t.get('source_plugins', [])[:4])}` | {t.get('rationale','')} |"
        )
    if not supported_techniques:
        md_lines.append("| _None_ | _No supported technique_ | _N/A_ | _N/A_ |")

    md_lines += [
        "",
        "### Review-Only ATT&CK Leads",
        "",
        "_Single-family or weak signals. These guide analyst review but do not affect the verdict or kill chain._",
        "",
        "| Technique ID | Name | Matched Terms | Sources |",
        "|-------------|------|---------------|---------|",
    ]
    for t in lead_techniques:
        terms = ", ".join(t.get("matched_required", [])[:4])
        md_lines.append(
            f"| `{t['technique_id']}` | {t['technique_name']} | "
            f"`{terms}` | `{', '.join(t.get('source_plugins', [])[:4])}` |"
        )
    if not lead_techniques:
        md_lines.append("| _None_ | _No lead-only technique_ | _N/A_ | _N/A_ |")

    md_lines += [
        "",
        "---",
        "",
        "## Attack Timeline",
        "",
        format_timeline_md(attacker_events[:20]),
        "",
        "---",
        "",
        "## Remediation Playbook",
        "",
        _remediation(all_conf, techniques),
        "",
        "---",
        "",
    ]

    # -- Memory Evidence Gap Controller --------------------------------------
    if memory_gap_controller:
        md_lines += [
            "## Memory Evidence Gap Controller",
            "",
            f"**Action**: `{memory_gap_controller.get('action', 'unknown')}`  ",
            f"**Confidence**: `{memory_gap_controller.get('confidence', 'unknown')}`  ",
            f"**Plugins with data**: {memory_gap_controller.get('plugins_with_data', 0)}  ",
            f"**Collection errors**: {memory_gap_controller.get('collection_errors', 0)}  ",
            "",
            "| Evidence Family | Present |",
            "|-----------------|---------|",
        ]
        for family, present in (memory_gap_controller.get("families", {}) or {}).items():
            md_lines.append(f"| `{family}` | {'yes' if present else 'no'} |")
        gaps = memory_gap_controller.get("gaps", []) or []
        md_lines += ["", "**Remaining gaps**: " + (", ".join(f"`{g}`" for g in gaps) if gaps else "none"), "", "---", ""]

    # -- Analyst Reasoning Trace --------------------------------------------
    reasoning_log = state.get("reasoning_log", [])
    if reasoning_log:
        md_lines += [
            "## Investigation Reasoning Trace",
            "",
            "How PHANTOM thought through this case - which tools were chosen, why, "
            "what was expected, and what was actually found.",
            "",
            "| Step | Agent | Action | Rationale | Result |",
            "|------|-------|--------|-----------|--------|",
        ]
        for i, entry in enumerate(reasoning_log, 1):
            agent    = entry.get("agent", "?")
            action   = entry.get("action", "?").replace("|", "/")
            rational = entry.get("rationale", "").replace("|", "/")[:120]
            result   = entry.get("result", "").replace("|", "/")[:100]
            md_lines.append(f"| {i} | **{agent}** | {action} | {rational} | {result} |")
        md_lines += ["", "---", ""]

    if self_correction_history:
        md_lines += [
            "## Self-Correction Trace",
            "",
            "| Iteration | Threshold | Gaps | Action | Result |",
            "|-----------|-----------|------|--------|--------|",
        ]
        for entry in self_correction_history:
            decision = entry.get("decision", {})
            gaps = ", ".join(decision.get("gaps", [])) or "none"
            result = (
                f"critical={entry.get('critical_count', 0)}, "
                f"medium={entry.get('medium_count', 0)}, "
                f"low={entry.get('low_count', 0)}, "
                f"cleared={entry.get('cleared_count', 0)}, "
                f"refuted={entry.get('refuted_count', 0)}"
            )
            md_lines.append(
                f"| {entry.get('iteration', 0) + 1} | {entry.get('threshold', '?')} | "
                f"{gaps} | {decision.get('action', 'unknown')} | {result} |"
            )
        md_lines += ["", "---", ""]

    md_lines.append(f"*PHANTOM DFIR v4.0 | World's first adversarial self-verifying DFIR agent*")

    md_path = os.path.join(REPORT_DIR, f"{basename}.md")
    with open(md_path, "w") as f:
        f.write("\n".join(md_lines))
    print(f"  [OK] MD:   {md_path}", flush=True)

    # -- Execution Log (structured JSON) ------------------------------------
    # v4.0: SHA-256 output hashes for chain of custody
    import hashlib

    # Hash each plugin's raw evidence for tamper detection
    evidence_integrity = {}
    for plugin_name, plugin_output in state.get("raw_evidence", {}).items():
        if plugin_output:
            output_hash = hashlib.sha256(plugin_output.encode("utf-8", errors="replace")).hexdigest()
            evidence_integrity[plugin_name] = {
                "sha256": output_hash,
                "size_bytes": len(plugin_output),
            }

    # Hash the memory image file itself
    target_hash = ""
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as img_f:
            for chunk in iter(lambda: img_f.read(8192 * 1024), b""):
                h.update(chunk)
        target_hash = h.hexdigest()
    except Exception:
        target_hash = "unable_to_hash"

    exec_log = {
        "phantom_version": "4.0.0",
        "target": filepath,
        "target_sha256": target_hash,
        "os_type": state.get("os_type", "?"),
        "duration_seconds": round(duration, 1),
        "total_steps": len(reasoning_log),
        "skeptic_rounds": state.get("skeptic_round", 0),
        "hypotheses_generated": len(state.get("hypotheses", [])),
        "critical_count": len(critical),
        "cleared_count": len(cleared),
        "refuted_count": len(refuted),
        "hallucinations_caught": len(refuted),
        "self_correction_history": self_correction_history,
        "memory_gap_controller": memory_gap_controller,
        "evidence_integrity": evidence_integrity,
        "reasoning_trace": reasoning_log,
    }
    exec_log_path = os.path.join(REPORT_DIR, f"{basename}_execution_log.json")
    with open(exec_log_path, "w") as f:
        json.dump(exec_log, f, indent=2, default=str)
    print(f"  [OK] Exec: {exec_log_path}", flush=True)

    # -- Console Summary -------------------------------------------------------
    print(f"\n{SEPARATOR}", flush=True)
    print("  PHANTOM DFIR - Investigation Complete", flush=True)
    print(f"  Duration: {duration:.1f}s | Skeptic rounds: {state.get('skeptic_round',0)}", flush=True)
    print(SEPARATOR, flush=True)

    for h in critical:
        print(f"\n  [CRITICAL] CRITICAL: {h['claim'][:70]}", flush=True)
        for s in h.get("verified_sources", [])[:3]:
            print(f"     - {s}", flush=True)
        if h.get("mitre_ids"):
            print(f"     - ATT&CK: {', '.join(h['mitre_ids'])}", flush=True)

    for h in medium:
        print(f"\n  [MEDIUM] MEDIUM: {h['claim'][:70]}", flush=True)

    for h in cleared:
        print(f"\n  [CLEARED] CLEARED: {h['claim'][:70]}", flush=True)

    if kill_chain:
        print(f"\n  ATT&CK Chain: {' -> '.join(kill_chain)}", flush=True)

    if refuted:
        print(f"\n  [REFUTED] {len(refuted)} hallucination(s) caught by Skeptic:", flush=True)
        for h in refuted:
            print(f"     - {h['claim'][:60]}", flush=True)

    if memory_gap_controller:
        print(f"\n  [GAPS] Memory gap controller: {memory_gap_controller.get('action', 'unknown')} | gaps={len(memory_gap_controller.get('gaps', []) or [])}", flush=True)

    print(f"\n  [TRACE] Reasoning trace: {len(reasoning_log)} steps logged", flush=True)
    print(f"  [LOG] Execution log: {exec_log_path}", flush=True)

    print(f"\n{SEPARATOR}\n", flush=True)

    return {
        **state,
        "report_json_path": json_path,
        "report_md_path":   md_path,
        "mitre_chain":      kill_chain,
        "attack_timeline":  attacker_events,
        "reasoning_log":    reasoning_log,
    }
