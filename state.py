"""
PHANTOM DFIR — Investigation State
Shared LangGraph TypedDict state passed between all agents.
"""
from typing import TypedDict, List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class EvidenceSource:
    """A single raw evidence entry tied to a tool run."""
    tool:    str        # e.g. "vol3:windows.pslist"
    command: str        # full command that was run
    output:  str        # raw stdout/stderr
    pid:     Optional[int] = None
    ip:      Optional[str] = None


@dataclass
class Hypothesis:
    """A finding proposed by the Investigator agent."""
    id:          str            # unique e.g. "H001"
    claim:       str            # "ruby.exe from services.exe = Metasploit"
    ioc:         str            # the specific IOC (PID, IP, filename)
    attack_phase: str           # "C2", "Malware", "LateralMovement", etc.
    supporting_evidence: List[EvidenceSource] = field(default_factory=list)
    skeptic_challenges:  List[str] = field(default_factory=list)
    verified_sources:    List[str] = field(default_factory=list)   # tools that confirmed
    confidence:          str = "UNVERIFIED"   # LOW / MEDIUM / CRITICAL / REFUTED
    mitre_ids:           List[str] = field(default_factory=list)


class InvestigationState(TypedDict):
    """Shared state for all LangGraph nodes."""

    # ── Input ────────────────────────────────────────────────────────────────
    filepath:     str            # path to memory image
    os_type:      str            # "windows" | "linux" | "unknown"
    vol3_profile: Optional[str]  # None (symbols auto) or string
    vol2_profile: Optional[str]  # e.g. "Win10x64_16299"
    engines:      Dict[str, str] # {"vol3": "/path/vol", "vol2": "/path/vol2"}

    # ── Raw evidence from collection phase ───────────────────────────────────
    raw_evidence: Dict[str, str]    # plugin_name -> raw output
    collection_errors: List[str]    # plugins that failed

    # ── Adversarial loop ─────────────────────────────────────────────────────
    hypotheses:      List[Dict]     # serialised Hypothesis objects
    skeptic_round:   int            # current debate round (0-3)

    # ── Verified findings ─────────────────────────────────────────────────────
    critical_findings: List[Dict]   # confidence=CRITICAL
    medium_findings:   List[Dict]   # confidence=MEDIUM
    low_findings:      List[Dict]   # confidence=LOW
    cleared_findings:  List[Dict]   # confidence=CLEARED — investigated, determined benign
    refuted:           List[Dict]   # Skeptic refuted — hallucinations caught

    # ── Final output ──────────────────────────────────────────────────────────
    attack_timeline:  List[Dict]    # chronological event list
    mitre_chain:      List[str]     # ordered ATT&CK IDs
    report_json_path: str
    report_md_path:   str
    duration_seconds: float
    start_time:       float          # unix timestamp at investigation start

    # ── Analyst Reasoning Trace ──────────────────────────────────────────────
    reasoning_log:    List[Dict]    # [{agent, action, rationale, result, timestamp}]
