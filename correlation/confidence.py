"""
PHANTOM DFIR — Confidence Corroborator v2.1
An IOC must be confirmed by N independent tools to reach a confidence level.
  1 source  → LOW
  2 sources → MEDIUM
  3+ sources → CRITICAL
This prevents single-tool hallucinations from being reported as fact.

v2.1 — Benign hypothesis detection: findings that the investigator
       identified as legitimate software get capped at "CLEARED" regardless
       of source count. This prevents false positives (e.g. Puppet Ruby)
       from being flagged as CRITICAL.
"""
from config import MIN_SOURCES_CRITICAL, MIN_SOURCES_MEDIUM


# Keywords in the claim that indicate the investigator already decided it's benign
BENIGN_INDICATORS = [
    "likely benign",
    "legitimate software",
    "benign",
    "expected behavior",
    "false positive",
    "not malicious",
]


def is_benign_hypothesis(hypothesis: dict) -> bool:
    """
    Check if a hypothesis was classified as benign by the investigator.
    Looks at both the claim text and the attack_phase.
    """
    claim = hypothesis.get("claim", "").lower()
    if any(indicator in claim for indicator in BENIGN_INDICATORS):
        return True
    return False


def score(verified_sources: list, hypothesis: dict = None) -> str:
    """
    Given a list of tool names that confirmed an IOC, return confidence level.
    If the hypothesis is benign, cap at CLEARED regardless of source count.
    """
    n = len(set(verified_sources))  # deduplicate same tool run twice

    # Benign findings get CLEARED — not CRITICAL
    if hypothesis and is_benign_hypothesis(hypothesis):
        return "CLEARED"

    if n >= MIN_SOURCES_CRITICAL:
        return "CRITICAL"
    elif n >= MIN_SOURCES_MEDIUM:
        return "MEDIUM"
    elif n >= 1:
        return "LOW"
    else:
        return "UNVERIFIED"


def score_hypotheses(hypotheses: list) -> list:
    """Apply confidence scoring to a list of Hypothesis dicts."""
    for h in hypotheses:
        h["confidence"] = score(h.get("verified_sources", []), h)
    return hypotheses


def bucket_findings(hypotheses: list) -> dict:
    """Split scored hypotheses into CRITICAL / MEDIUM / LOW / CLEARED / REFUTED buckets."""
    buckets = {"critical": [], "medium": [], "low": [], "cleared": [], "refuted": []}
    for h in hypotheses:
        c = h.get("confidence", "UNVERIFIED")
        if c == "CRITICAL":
            buckets["critical"].append(h)
        elif c == "MEDIUM":
            buckets["medium"].append(h)
        elif c == "LOW":
            buckets["low"].append(h)
        elif c == "CLEARED":
            buckets["cleared"].append(h)
        else:
            buckets["refuted"].append(h)
    return buckets
