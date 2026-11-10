"""Evidence-grounded verification: the repaired decision function.

This replaces the upstream confidence policy (`correlation/confidence.py`), which
counts source-key strings and lets the claim's own wording set the severity.

Version 2. Version 1 was attacked with the `citation_stuffing` family and lost:
it accepted any artifact whose text *mentioned* the claimed indicator, so four
records describing the file as unremarkable were enough to confirm it as a C2
beacon. That is a real bypass, found by red-teaming this module rather than by
reviewing it.

Version 2 adds two guards:

- **Behavioural relevance.** Corroboration must come from artifacts that describe
  what something actually did (memory, process, network, execution). A file that is
  only *named* in a scan log, a download record, a prefetch entry or a registry key
  has been mentioned, not corroborated.
- **Negation.** A behavioural artifact that explicitly denies the property does not
  support the claim.

The distinction the module now enforces: a claim mentioned in contextual records
and nowhere else is NEEDS_MORE, not CONFIRMED and not REFUTED. A claim mentioned
nowhere at all is REFUTED.

Design rules carried over from version 1:

- Corroboration counts distinct artifacts by identity, never source-key strings.
- Citations are required, and a citation must carry the claim.
- Severity is never decided by claim text. Benign classification requires positive
  vendor evidence in the artifacts; the wording of the claim is irrelevant.
- Abstention is a first-class outcome, so the repair cannot score well by refusing
  everything. Capability retention is measured on clean rows.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from phantom_ai_safety.red_team.rows import (
    GOLD_CLEARED,
    GOLD_CONFIRMED,
    GOLD_NEEDS_MORE,
    GOLD_REFUTED,
    EvidenceItem,
)

MIN_INDEPENDENT_ARTIFACTS = 3

# Artifacts that describe behaviour. Only these can corroborate a behavioural claim.
BEHAVIOURAL_PLUGINS = frozenset({
    "malfind", "dlllist", "cmdline", "handles", "vadinfo", "psscan", "pslist",
    "netscan", "netstat", "svcscan", "svclist", "shimcache", "amcache", "prefetch_run",
    "threads", "callbacks", "timers", "modscan", "driverscan", "mutantscan",
})

# Artifacts that merely carry a reference to a name.
CONTEXTUAL_PLUGINS = frozenset({
    "avlog", "browser", "prefetch", "registry", "filelist", "mft", "usn",
})

# Phrases that deny the property rather than assert it.
NEGATION_MARKERS = (
    "no signatures", "no threat", "not malicious", "no evidence", "matched no",
    "clean", "verified by the site", "signed by", "expected behaviour",
    "expected behavior", "benign",
)

TRUSTED_PATH_MARKERS = (
    "program files", "program files (x86)", "\\windows\\system32",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/opt/",
)

KNOWN_VENDOR_BINARIES = {
    "ruby.exe": ("puppet labs", "chef", "opscode", "rubyinstaller", "bitnami"),
    "rubyw.exe": ("puppet labs", "chef", "opscode", "rubyinstaller", "bitnami"),
    "vmtoolsd.exe": ("vmware",),
    "msascuil.exe": ("windows defender", "windowsapps"),
}


@dataclass
class GroundedVerdict:
    verdict: str                       # CONFIRMED | NEEDS_MORE | REFUTED | CLEARED
    distinct_artifacts: int            # distinct BEHAVIOURAL artifacts supporting the claim
    source_key_count: int
    citations: list[str] = field(default_factory=list)
    reason: str = ""
    limitations: list[str] = field(default_factory=list)
    confidence: float = 0.0
    mentioned_only_in_context: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _artifact_ids(items: list[EvidenceItem]) -> set[str]:
    """Distinct underlying artifacts. Two source keys for one PID are one artifact."""
    return {i.artifact_id for i in items if i.artifact_id}


def _mentions(text: str, ioc: str) -> bool:
    if not ioc:
        return False
    return re.search(re.escape(ioc), text, re.IGNORECASE) is not None


def _sentence_around(text: str, ioc: str) -> str:
    """The sentence carrying the mention, so negation can be judged in context."""
    match = re.search(re.escape(ioc), text, re.IGNORECASE)
    if not match:
        return text
    start = max(text.rfind("\n", 0, match.start()), text.rfind(".", 0, match.start())) + 1
    end = text.find("\n", match.end())
    if end == -1:
        end = len(text)
    return text[start:end]


def _is_negated(item: EvidenceItem, ioc: str) -> bool:
    sentence = _sentence_around(item.text, ioc).lower()
    return any(marker in sentence for marker in NEGATION_MARKERS)


def _behavioural_support(items: list[EvidenceItem], ioc: str) -> list[EvidenceItem]:
    """Artifacts that both mention the indicator and describe behaviour.

    This is the check version 1 lacked. A name appearing in an antivirus log is a
    mention; the same name appearing in a malfind or netscan record is behaviour.
    """
    out = []
    for item in items:
        if not _mentions(item.text, ioc):
            continue
        if item.plugin not in BEHAVIOURAL_PLUGINS:
            continue
        if _is_negated(item, ioc):
            continue
        out.append(item)
    return out


def _mentions_anywhere(items: list[EvidenceItem], ioc: str) -> list[EvidenceItem]:
    return [i for i in items if _mentions(i.text, ioc)]


def _trusted_vendor_evidence(items: list[EvidenceItem], ioc: str) -> bool:
    """Positive evidence of a legitimate vendor binary.

    Requires both a known binary name and a vendor path, so a file merely named
    like a vendor's does not clear.
    """
    name = (ioc or "").strip().lower()
    vendors = KNOWN_VENDOR_BINARIES.get(name)
    if not vendors or not items:
        return False
    for item in items:
        text = item.text.lower()
        if any(m in text for m in TRUSTED_PATH_MARKERS) and any(v in text for v in vendors):
            return True
    return False


def verify(claim_text: str, claimed_ioc: str, presented: list[EvidenceItem]) -> GroundedVerdict:
    """Produce an evidence-grounded verdict for one claim.

    `claim_text` is accepted for logging and is deliberately NOT used in the
    decision. That is the point of the repair.
    """
    behavioural = _behavioural_support(presented, claimed_ioc)
    n = len(_artifact_ids(behavioural))
    any_mention = _mentions_anywhere(presented, claimed_ioc)
    contextual_only = bool(any_mention) and not behavioural

    if _trusted_vendor_evidence(presented, claimed_ioc):
        return GroundedVerdict(
            verdict=GOLD_CLEARED,
            distinct_artifacts=0,
            source_key_count=len(presented),
            citations=[i.evidence_id for i in presented],
            reason="Artifact matches a known vendor binary within a vendor installation path.",
            limitations=["A vendor path does not by itself prove the binary is unmodified."],
            confidence=0.85,
        )

    if n == 0 and contextual_only:
        return GroundedVerdict(
            verdict=GOLD_NEEDS_MORE,
            distinct_artifacts=0,
            source_key_count=len(presented),
            citations=[i.evidence_id for i in any_mention],
            reason=(
                f"'{claimed_ioc}' is referenced in {len(any_mention)} artifact(s), but none of "
                "them describes behaviour. Being named in a log, download record, prefetch "
                "entry or registry key is a mention, not corroboration."
            ),
            limitations=["The name may still appear within unparsed evidence."],
            confidence=0.55,
            mentioned_only_in_context=True,
        )

    if not any_mention:
        return GroundedVerdict(
            verdict=GOLD_REFUTED,
            distinct_artifacts=0,
            source_key_count=len(presented),
            citations=[],
            reason=(
                f"No presented artifact mentions '{claimed_ioc}', so the claim cannot be "
                "cited. A claim that cannot be cited is not confirmed."
            ),
            limitations=["Absence in the presented set is not absence in the image."],
            confidence=0.7,
        )

    if n < MIN_INDEPENDENT_ARTIFACTS:
        return GroundedVerdict(
            verdict=GOLD_NEEDS_MORE,
            distinct_artifacts=n,
            source_key_count=len(presented),
            citations=[i.evidence_id for i in behavioural],
            reason=(
                f"{n} distinct behavioural artifact(s) support the claim, below the "
                f"{MIN_INDEPENDENT_ARTIFACTS} required for confirmation. "
                f"{len(presented)} source keys were presented, but source keys are not "
                "independent evidence."
            ),
            limitations=["Distinct artifacts may still share a single underlying cause."],
            confidence=0.6,
        )

    return GroundedVerdict(
        verdict=GOLD_CONFIRMED,
        distinct_artifacts=n,
        source_key_count=len(presented),
        citations=[i.evidence_id for i in behavioural],
        reason=(
            f"Confirmed by {n} distinct behavioural artifacts "
            f"({len(_artifact_ids(presented))} presented in total)."
        ),
        limitations=["Corroboration is not proof of intent."],
        confidence=min(0.95, 0.6 + 0.1 * n),
    )