"""
PHANTOM DFIR - Skeptic Agent
Challenges every hypothesis the Investigator makes.
A finding ONLY becomes CRITICAL if it survives the Skeptic's challenge
using raw evidence - not just LLM reasoning.

This is the core anti-hallucination mechanism.

v1.1 - Fixed NEEDS_MORE override bug: if 3+ sources confirm, always CRITICAL
       Fixed skeptic prompt to respect evidence count rule
       Added JSON control char stripping (same as investigator)
"""
import json
import re
from langchain_core.prompts import PromptTemplate

from state import InvestigationState
from config import OLLAMA_BASE_URL, OLLAMA_MODEL, TIMEOUT_LLM, MAX_SKEPTIC_ROUNDS
from correlation.confidence import score, bucket_findings, is_benign_hypothesis
from tools.llm_provider import create_llm
from tools.skills_loader import load_skills_for_phase

llm = create_llm(temperature=0.0)  # Skeptic must be deterministic

SKEPTIC_PROMPT = PromptTemplate.from_template("""
You are an adversarial reviewer of a DFIR investigation.
Your job: challenge each hypothesis ONLY if the evidence does NOT support it.
{skill_context}

=== ABSOLUTE RULES (never break these) ===
1. If verified_sources_count >= 3: verdict MUST be "CONFIRMED" - no exceptions
2. If verified_sources_count == 0: verdict MUST be "REFUTED"
3. If verified_sources_count is 1 or 2: verdict is "NEEDS_MORE"
4. You CANNOT say NEEDS_MORE or REFUTED when there are 3+ sources
5. The source count is objective fact - do not second-guess it

=== HYPOTHESES WITH EVIDENCE ===
{hypotheses_json}
================================

For each hypothesis, apply the rules above strictly.
Return a JSON array - one entry per hypothesis:
{{
  "id": "H001",
  "verdict": "CONFIRMED | NEEDS_MORE | REFUTED",
  "reason": "One sentence. If CONFIRMED with 3+ sources, say 'Confirmed by N independent sources across plugins X, Y, Z'",
  "additional_checks": []
}}

Return ONLY a valid JSON array, no other text.
""")


def _strip_control_chars(text: str) -> str:
    """Strip control characters that break JSON parsing."""
    text = text.replace('\t', ' ')
    text = text.replace('\r', ' ')
    text = re.sub(r'[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


def _format_hypotheses_for_skeptic(hypotheses: list) -> str:
    """Compact JSON of hypotheses for the Skeptic prompt."""
    summary = []
    for h in hypotheses:
        n = len(h.get("verified_sources", []))
        summary.append({
            "id":                     h["id"],
            "claim":                  h["claim"],
            "ioc":                    h["ioc"],
            "attack_phase":           h.get("attack_phase", ""),
            "verified_sources_count": n,
            "verified_sources":       h.get("verified_sources", [])[:5],
            "raw_evidence_quote":     h.get("raw_evidence_quote", "")[:200],
            # Explicitly tell the LLM what verdict is required
            "required_verdict":       "CONFIRMED" if n >= 3 else ("REFUTED" if n == 0 else "NEEDS_MORE"),
        })
    return json.dumps(summary, indent=2)


def _rule_based_skeptic(hypotheses: list) -> list:
    """
    Pure rule-based skeptic (no LLM) - fallback if Ollama is unavailable.
    Always correct - never hallucinates.
    """
    verdicts = []
    for h in hypotheses:
        n = len(h.get("verified_sources", []))
        if n >= 3:
            verdicts.append({
                "id":      h["id"],
                "verdict": "CONFIRMED",
                "reason":  f"Confirmed by {n} independent sources",
                "additional_checks": [],
            })
        elif n >= 1:
            verdicts.append({
                "id":      h["id"],
                "verdict": "NEEDS_MORE",
                "reason":  f"Only {n} source(s) - need 3+ to be CRITICAL",
                "additional_checks": ["Run targeted PID/IP re-query"],
            })
        else:
            verdicts.append({
                "id":      h["id"],
                "verdict": "REFUTED",
                "reason":  "Zero evidence sources confirm this claim",
                "additional_checks": [],
            })
    return verdicts


def _enforce_evidence_rules(verdict: str, reason: str, n: int) -> tuple:
    """
    Hard override: evidence count always wins over LLM opinion.
    This is the core fix for the NEEDS_MORE bug.

    If the LLM says NEEDS_MORE but there are 3+ sources -> override to CONFIRMED.
    If the LLM says CONFIRMED but there are 0 sources -> override to REFUTED.
    """
    if n >= 3 and verdict != "CONFIRMED":
        return (
            "CONFIRMED",
            f"[AUTO-CONFIRMED: {n} sources override LLM verdict '{verdict}'] {reason}"
        )
    if n == 0 and verdict == "CONFIRMED":
        return (
            "REFUTED",
            f"[AUTO-REFUTED: 0 sources override LLM verdict 'CONFIRMED'] {reason}"
        )
    return verdict, reason


def run_skeptic(state: InvestigationState) -> InvestigationState:
    """LangGraph node: Skeptic challenges all hypotheses."""
    hypotheses = state.get("hypotheses", [])
    round_num  = state.get("skeptic_round", 0) + 1

    print("\n==================================================", flush=True)
    print(f"  PHASE 4 - SKEPTIC AGENT (Round {round_num}/{MAX_SKEPTIC_ROUNDS})", flush=True)
    print("==================================================", flush=True)

    import time as _time
    reasoning = state.get("reasoning_log", [])

    hyp_json = _format_hypotheses_for_skeptic(hypotheses)

    # Try LLM skeptic first unless --no-llm disabled it in main.py.
    skill_context = load_skills_for_phase("skeptic")
    verdicts = None
    if llm is None:
        print("  -> Rule-based skeptic active (--no-llm)", flush=True)
    else:
        try:
            chain  = SKEPTIC_PROMPT | llm
            output = chain.invoke({
                "hypotheses_json": hyp_json,
                "skill_context": skill_context,
            })
            start  = output.find("[")
            end    = output.rfind("]") + 1
            if start == -1:
                raise ValueError("No JSON array in Skeptic response")
            clean = _strip_control_chars(output[start:end])
            verdicts = json.loads(clean)
        except Exception as e:
            print(f"  [!] Skeptic LLM error: {e} - using rule-based skeptic", flush=True)

    # Always fall back to rule-based if LLM failed
    if not verdicts:
        verdicts = _rule_based_skeptic(hypotheses)

    # Build verdict lookup
    verdict_map = {v["id"]: v for v in verdicts}

    updated = []
    for h in hypotheses:
        v       = verdict_map.get(h["id"], {})
        verdict = v.get("verdict", "NEEDS_MORE")
        reason  = v.get("reason", "")
        sources = h.get("verified_sources", [])
        n       = len(sources)

        # -- CORE FIX: hard-enforce evidence count rules --------------------
        verdict, reason = _enforce_evidence_rules(verdict, reason, n)

        # Record the challenge
        h["skeptic_challenges"].append(f"Round {round_num}: {verdict} - {reason}")

        # Assign confidence
        if verdict == "REFUTED" and n == 0:
            h["confidence"] = "REFUTED"
        else:
            h["confidence"] = score(sources, h)

        emoji = {
            "CRITICAL":   "[CRITICAL]",
            "MEDIUM":     "[MEDIUM]",
            "LOW":        "[LOW]",
            "CLEARED":    "[CLEARED]",
            "REFUTED":    "[REFUTED]",
            "UNVERIFIED": "[UNVERIFIED]",
        }.get(h["confidence"], "[UNKNOWN]")

        print(f"  {emoji} {h['id']}: {h['confidence']} ({n} sources) - {reason[:80]}", flush=True)

        # Reasoning trace
        reasoning.append({
            "agent": "Skeptic",
            "action": f"Challenge {h['id']} ({h['ioc']})",
            "rationale": f"Demanded {n} independent evidence sources. "
                         f"Verdict={verdict}: {reason[:100]}",
            "result": f"Confidence={h['confidence']} - "
                      f"{'benign (CLEARED)' if h['confidence'] == 'CLEARED' else f'{n} sources confirmed'}",
            "timestamp": _time.time(),
        })

        updated.append(h)

    # Bucket findings by confidence
    buckets = bucket_findings(updated)

    # Merge any findings already cleared by the legitimacy engine.
    # Skeptic can run multiple rounds; keep one canonical CLEARED record per IOC
    # so reports do not repeat the same benign process.
    existing_cleared = state.get("cleared_findings", [])
    all_cleared = []
    seen_cleared = set()
    for item in existing_cleared + buckets["cleared"]:
        key = (item.get("ioc") or item.get("claim") or "").lower().strip()
        if not key or key in seen_cleared:
            continue
        seen_cleared.add(key)
        all_cleared.append(item)

    return {
        **state,
        "hypotheses":        updated,
        "skeptic_round":     round_num,
        "critical_findings": buckets["critical"],
        "medium_findings":   buckets["medium"],
        "low_findings":      buckets["low"],
        "cleared_findings":  all_cleared,
        "refuted":           buckets["refuted"],
        "reasoning_log":     reasoning,
    }


def should_continue_debate(state: InvestigationState) -> str:
    """
    LangGraph conditional edge: continue debate if round < MAX and
    there are still UNVERIFIED/LOW hypotheses with < 3 sources.
    Otherwise go to reporter.
    """
    round_num  = state.get("skeptic_round", 0)
    hypotheses = state.get("hypotheses", [])

    # Only re-run evidence for genuinely under-evidenced hypotheses
    unverified = [
        h for h in hypotheses
        if h.get("confidence") in ("UNVERIFIED", "LOW")
        and len(h.get("verified_sources", [])) < 3
    ]

    if round_num < MAX_SKEPTIC_ROUNDS and unverified:
        print(
            f"\n  -> {len(unverified)} hypotheses still need more evidence. "
            f"Running evidence agent again (round {round_num + 1})...",
            flush=True
        )
        return "evidence"
    else:
        print(
            f"\n  -> Debate complete after {round_num} round(s). Generating report.",
            flush=True
        )
        decision = "reporter"

    # -- Persistent Learning Loop: write progress file --------------------
    _write_progress_file(state, round_num, decision)
    return decision


def _write_progress_file(state: dict, round_num: int, decision: str):
    """
    Write a progress file after each skeptic round.
    Tracks improvement between iterations - demonstrates self-correction.
    """
    import json, os, time as _time
    from config import REPORT_DIR

    filepath = state.get("filepath", "unknown")
    target   = os.path.basename(filepath).replace(" ", "_")
    progress_path = os.path.join(REPORT_DIR, f"phantom_{target}_progress.json")

    hypotheses = state.get("hypotheses", [])
    # Tally current state
    conf_counts = {}
    for h in hypotheses:
        c = h.get("confidence", "UNVERIFIED")
        conf_counts[c] = conf_counts.get(c, 0) + 1

    sources_per_hyp = [len(h.get("verified_sources", [])) for h in hypotheses]
    avg_sources = sum(sources_per_hyp) / max(len(sources_per_hyp), 1)

    round_entry = {
        "round": round_num,
        "decision": decision,
        "confidence_distribution": conf_counts,
        "avg_evidence_sources": round(avg_sources, 1),
        "unverified_remaining": conf_counts.get("UNVERIFIED", 0) + conf_counts.get("LOW", 0),
        "critical_count": conf_counts.get("CRITICAL", 0),
        "cleared_count": conf_counts.get("CLEARED", 0),
        "refuted_count": conf_counts.get("REFUTED", 0),
        "timestamp": _time.time(),
    }

    # Load existing progress or create new
    progress = {"target": filepath, "max_iterations": MAX_SKEPTIC_ROUNDS, "rounds": []}
    if os.path.exists(progress_path):
        try:
            with open(progress_path) as f:
                progress = json.load(f)
        except Exception:
            pass

    progress["rounds"].append(round_entry)

    # Calculate improvement between first and current round
    if len(progress["rounds"]) > 1:
        first = progress["rounds"][0]
        last  = round_entry
        progress["improvement"] = {
            "avg_sources_change": round(
                last["avg_evidence_sources"] - first["avg_evidence_sources"], 1),
            "unverified_reduction": first["unverified_remaining"] - last["unverified_remaining"],
            "critical_gain": last["critical_count"] - first.get("critical_count", 0),
            "self_correction_demonstrated": last["unverified_remaining"] < first["unverified_remaining"],
        }

    progress["final_decision"] = decision

    try:
        with open(progress_path, "w") as f:
            json.dump(progress, f, indent=2, default=str)
    except Exception:
        pass
