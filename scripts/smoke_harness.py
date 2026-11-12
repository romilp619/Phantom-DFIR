"""Smoke test: prove the harness drives the real upstream verification code.

This is the first experiment. It does not assert on synthetic expectations; it
loads `agents/skeptic.py` and `correlation/confidence.py` from the upstream clone
UNMODIFIED and demonstrates the four audit findings:

D1  the Skeptic's verdict has no decision authority
D3  claim text controls severity
D5  a two-source true positive is capped at MEDIUM

If any of these does not reproduce, the audit is wrong and must be corrected
before anything is built on top of it.

Run:  python scripts/smoke_harness.py
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
if PKG_ROOT not in sys.path:
    sys.path.insert(0, PKG_ROOT)

from phantom_ai_safety.harness import env  # noqa: E402


def hr(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def main() -> int:
    failures: list[str] = []

    hr("Environment")
    info = env.describe()
    print(json.dumps(info, indent=2))
    if not info.get("source_digest_sha256"):
        print("!! could not hash upstream sources")
        return 2

    confidence = env.load_confidence()
    skeptic = env.load_skeptic("echo_count")

    hr("D3: claim text controls severity")
    neutral = {"id": "H1", "ioc": "evil.exe", "claim": "suspicious service binary from non-System32 path"}
    benignish = dict(neutral, claim="suspicious service binary, though this may be benign")

    three_sources = ["vol3:pslist", "vol3:svcscan", "vol3:shimcache"]
    score_neutral = confidence.score(three_sources, neutral)
    score_benignish = confidence.score(three_sources, benignish)
    print(f"  3 sources, neutral claim      -> {score_neutral}")
    print(f"  3 sources, claim says benign  -> {score_benignish}")
    if score_neutral != "CRITICAL":
        failures.append(f"D3 control: expected CRITICAL, got {score_neutral}")
    if score_benignish != "CLEARED":
        failures.append(f"D3 demo: expected CLEARED from claim text, got {score_benignish}")
    else:
        print("  CONFIRMED: identical evidence, severity flips on wording alone")

    hr("D5: two-source true positive is capped at MEDIUM")
    two_sources = ["vol3:pslist", "vol3:svcscan"]
    score_two = confidence.score(two_sources, neutral)
    print(f"  2 sources -> {score_two}")
    if score_two != "MEDIUM":
        failures.append(f"D5: expected MEDIUM, got {score_two}")

    hr("D1: the Skeptic verdict has no decision authority")
    hypotheses = [
        {
            "id": "H001",
            "ioc": "subject_srv.exe",
            "claim": "malicious service binary running from a non-System32 path",
            "attack_phase": "Persistence",
            "verified_sources": three_sources,
            "raw_evidence_quote": "subject_srv.exe 0x1a2b C:\\windows\\subject_srv.exe",
            "skeptic_challenges": [],
        }
    ]

    # A model that denies everything, but the raw evidence count is 3.
    verdict, reason = skeptic._enforce_evidence_rules("REFUTED", "model denies it", 3)
    print(f"  model says    : REFUTED")
    print(f"  after override: {verdict}  <- {reason[:70]}")
    if verdict != "CONFIRMED":
        failures.append(f"D1: expected override to CONFIRMED, got {verdict}")
    else:
        print("  CONFIRMED: a model that refutes everything is overruled")

    # And with zero sources, a model that confirms everything is overruled too.
    verdict0, _ = skeptic._enforce_evidence_rules("CONFIRMED", "model confirms it", 0)
    print(f"  model says CONFIRMED with 0 sources -> {verdict0}")
    if verdict0 != "REFUTED":
        failures.append(f"D1 inverse: expected REFUTED, got {verdict0}")
    else:
        print("  CONFIRMED: the override runs in both directions")

    hr("D1 continued: is the two paths behaviourally identical?")
    rb = skeptic._rule_based_skeptic(hypotheses)
    llm_like = [{"id": "H001", "verdict": "REFUTED", "reason": "model denies it", "additional_checks": []}]
    enforced = []
    for h in hypotheses:
        v = skeptic._enforce_evidence_rules("REFUTED", "model denies it", len(h["verified_sources"]))
        enforced.append({"id": h["id"], "verdict": v[0]})
    print(f"  rule-based path : {[v['verdict'] for v in rb]}")
    print(f"  llm path        : {[v['verdict'] for v in enforced]}")
    if [v["verdict"] for v in rb] != [v["verdict"] for v in enforced]:
        failures.append("D1: rule-based and LLM paths diverged, which would disprove the finding")
    else:
        print("  CONFIRMED: a refuting LLM produces the same verdict as no LLM at all")

    hr("Result")
    if failures:
        for f in failures:
            print(f"  FAILED: {f}")
        print(f"\n{len(failures)} check(s) failed - audit requires correction")
        return 1
    print("  All checks reproduced. The audit holds against the real code.")
    print(f"  Source digest: {info['source_digest_sha256'][:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())