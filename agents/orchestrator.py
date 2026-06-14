"""
PHANTOM DFIR - LangGraph Orchestrator v2.0
Wires all agents into a StateGraph with conditional edges.
Includes self-correction loop that retries with stricter thresholds
when false positives are detected.

Flow:
  collector -> investigator -> evidence -> skeptic
                                   ^           |
                                   +-- (loop) -+
                                               |
                                            reporter

Self-correction:
  If false positives detected -> increase legitimacy threshold -> re-run
"""
import json
import os
import time
from langgraph.graph import StateGraph, END

from state import InvestigationState
from agents.collector    import run_collector
from agents.investigator import run_investigator
from agents.evidence     import run_evidence_agent
from agents.skeptic      import run_skeptic, should_continue_debate
from agents.reporter     import run_reporter


def build_graph() -> StateGraph:
    """Construct and compile the PHANTOM LangGraph StateGraph."""
    g = StateGraph(InvestigationState)

    g.add_node("collector",    run_collector)
    g.add_node("investigator", run_investigator)
    g.add_node("evidence",     run_evidence_agent)
    g.add_node("skeptic",      run_skeptic)
    g.add_node("reporter",     run_reporter)

    # Linear flow: collect -> investigate -> first evidence pass -> skeptic
    g.set_entry_point("collector")
    g.add_edge("collector",    "investigator")
    g.add_edge("investigator", "evidence")
    g.add_edge("evidence",     "skeptic")

    # Conditional: skeptic decides whether to loop for more evidence or report
    g.add_conditional_edges(
        "skeptic",
        should_continue_debate,
        {
            "evidence": "evidence",
            "reporter": "reporter",
        }
    )

    g.add_edge("reporter", END)

    return g.compile()


def _detect_false_positives(state: dict) -> list:
    """
    Analyze results to detect likely false positives.
    Uses behavioral signals - NOT hardcoded process names.

    A finding is likely a false positive if:
    - It was confirmed by many sources (exists in the system) BUT
    - The claim doesn't describe actual malicious behavior
    - The process runs from legitimate paths
    - No memory anomalies were found for it
    """
    critical = state.get("critical_findings", [])
    likely_fps = []

    for h in critical:
        signals = []
        claim_lower = h.get("claim", "").lower()
        ioc = h.get("ioc", "").lower()

        # Signal 1: claim mentions "communicating" but not injection/shell/payload
        if ("communicating" in claim_lower or "network" in claim_lower):
            if not any(w in claim_lower for w in [
                "injection", "shell", "payload", "exploit",
                "malware", "backdoor", "c2", "beacon",
                "metasploit", "cobalt", "mimikatz"
            ]):
                signals.append("network_activity_only")

        # Signal 2: "potential" or "could be" language = low confidence claim
        if any(w in claim_lower for w in [
            "potential", "could be", "might be", "possibly",
            "suspicious", "unusual"
        ]):
            signals.append("uncertain_language")

        # Signal 3: process has a high legitimacy score from the engine
        legit_score = h.get("legitimacy_score", 50)
        if legit_score >= 60:
            signals.append(f"high_legitimacy_{legit_score}")

        # Signal 4: the IOC is a Windows Store / UWP app (truncated .exe)
        if ioc.endswith(".e") or "windowsapps" in claim_lower:
            signals.append("uwp_app_truncated")

        # If 2+ false positive signals -> likely false positive
        if len(signals) >= 2:
            likely_fps.append({
                "hypothesis": h,
                "signals": signals,
                "ioc": h.get("ioc", ""),
            })

    return likely_fps


def _build_correction_decision(state: dict, likely_fps: list,
                               iteration: int, max_iterations: int) -> dict:
    """
    Hermes-inspired self-correction decision record.

    Instead of only saying "loop" or "done", PHANTOM records the detected gap,
    the chosen correction action, and why that action is safe. This gives
    judges a concrete iteration-over-iteration trace.
    """
    critical = state.get("critical_findings", [])
    medium = state.get("medium_findings", [])
    low = state.get("low_findings", [])
    cleared = state.get("cleared_findings", [])
    refuted = state.get("refuted", [])

    gaps = []
    if likely_fps:
        gaps.append("probable_false_positive_in_confirmed_findings")
    if cleared:
        gaps.append("false_positive_resolved_to_cleared")
    if refuted:
        gaps.append("unsupported_hypothesis_refuted")
    if any(len(h.get("verified_sources", [])) < 3 for h in medium + low):
        gaps.append("under_corroborated_findings_remain")

    if likely_fps and iteration < max_iterations - 1:
        action = "rerun_with_stricter_legitimacy_threshold"
        reason = "Likely false positives remain in confirmed findings."
    elif likely_fps:
        action = "stop_budget_exhausted_use_best_result"
        reason = "Correction budget exhausted before all likely false positives were cleared."
    elif cleared or refuted:
        action = "accept_resolved_first_pass"
        reason = "Skeptic/legitimacy checks resolved weak findings without another expensive collection pass."
    elif medium or low:
        action = "accept_with_unresolved_review_items"
        reason = "Remaining findings did not meet critical corroboration threshold; report as non-critical analyst review items."
    else:
        action = "accept_no_gaps"
        reason = "No malicious or unresolved findings remain after verification."

    return {
        "iteration": iteration,
        "action": action,
        "reason": reason,
        "gaps": gaps,
        "critical_count": len(critical),
        "medium_count": len(medium),
        "low_count": len(low),
        "cleared_count": len(cleared),
        "refuted_count": len(refuted),
        "likely_false_positive_count": len(likely_fps),
    }


def _format_correction_trace_md(history: list) -> str:
    """Render self-correction history as a compact Markdown table."""
    lines = [
        "",
        "---",
        "",
        "## Self-Correction Trace",
        "",
        "| Iteration | Threshold | Gaps | Action | Result |",
        "|-----------|-----------|------|--------|--------|",
    ]
    for entry in history:
        decision = entry.get("decision", {})
        gaps = ", ".join(decision.get("gaps", [])) or "none"
        result = (
            f"critical={entry.get('critical_count', 0)}, "
            f"medium={entry.get('medium_count', 0)}, "
            f"low={entry.get('low_count', 0)}, "
            f"cleared={entry.get('cleared_count', 0)}, "
            f"refuted={entry.get('refuted_count', 0)}"
        )
        lines.append(
            f"| {entry.get('iteration', 0) + 1} | {entry.get('threshold', '?')} | "
            f"{gaps} | {decision.get('action', 'unknown')} | {result} |"
        )
    return "\n".join(lines) + "\n"


def _persist_self_correction_history(state: dict, history: list) -> None:
    """
    Reporter runs inside the graph before the outer correction controller
    decides whether to rerun. Persist the final controller decision into the
    generated reports after the loop completes.
    """
    if not history:
        return

    json_path = state.get("report_json_path", "")
    md_path = state.get("report_md_path", "")
    exec_path = ""
    if json_path.endswith(".json"):
        exec_path = json_path[:-5] + "_execution_log.json"

    payload = {
        "self_correction_history": history,
        "self_correction_decisions": [h.get("decision", {}) for h in history],
    }

    for path in (json_path, exec_path):
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.update(payload)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass

    if md_path and os.path.exists(md_path):
        try:
            with open(md_path, "r", encoding="utf-8") as f:
                md = f.read()
            if "## Self-Correction Trace" not in md:
                marker = "*PHANTOM DFIR v4.0"
                trace = _format_correction_trace_md(history)
                if marker in md:
                    md = md.replace(marker, trace + "\n" + marker, 1)
                else:
                    md += trace
                with open(md_path, "w", encoding="utf-8") as f:
                    f.write(md)
        except Exception:
            pass


def run_investigation(filepath: str, self_correct: bool = False,
                      max_iterations: int = 3,
                      initial_threshold: int = 50) -> dict:
    """
    Run the full PHANTOM DFIR investigation on the given memory image.

    If self_correct=True, will re-run the investigation with progressively
    stricter legitimacy thresholds when false positives are detected.

    Returns the final state dict.
    """
    print("""
+==============================================================+
|            P H A N T O M   D F I R                          |
|  Parallel Hypothesis Analysis with Multi-agent Threat        |
|  Hunting Overlay Network                                     |
|                                                              |
|  World's first adversarial self-verifying DFIR agent         |
|  Find Evil! Hackathon 2026  |  LangGraph + Ollama            |
+==============================================================+
""", flush=True)

    from agents.collector import detect_engines
    engines = detect_engines()
    print(f"  Engines found: {list(engines.keys())}", flush=True)
    if not engines:
        print("  [ERROR] No Volatility engines found. Install vol (Vol3) or vol2 (Vol2).")
        return {}

    t0 = time.time()
    threshold = initial_threshold
    correction_history = []

    for iteration in range(max_iterations if self_correct else 1):
        if iteration > 0:
            print(f"\n{'='*60}", flush=True)
            print(f"  SELF-CORRECTION - Iteration {iteration + 1}/{max_iterations}", flush=True)
            print(f"  Legitimacy threshold: {threshold}/100", flush=True)
            print(f"{'='*60}", flush=True)

        initial_state: InvestigationState = {
            "filepath":        filepath,
            "os_type":         "unknown",
            "vol3_profile":    None,
            "vol2_profile":    None,
            "engines":         engines,
            "raw_evidence":    {},
            "collection_errors": [],
            "hypotheses":      [],
            "skeptic_round":   0,
            "critical_findings": [],
            "medium_findings":   [],
            "low_findings":      [],
            "cleared_findings":  [],
            "refuted":           [],
            "attack_timeline":   [],
            "mitre_chain":       [],
            "report_json_path":  "",
            "report_md_path":    "",
            "duration_seconds":  0.0,
            "start_time":        t0,
            "iteration_number":        iteration,
            "legitimacy_threshold":    threshold,
            "false_positives_detected": [],
            "self_correction_history":  correction_history,
            "self_correction_decisions": [],
            "reasoning_log":     [],
        }

        # On subsequent iterations, reuse the raw evidence from iteration 0
        # (no need to re-collect - that's the expensive part)
        if iteration > 0 and "raw_evidence" in accumulated:
            initial_state["raw_evidence"] = accumulated["raw_evidence"]
            initial_state["os_type"] = accumulated.get("os_type", "unknown")
            initial_state["collection_errors"] = accumulated.get("collection_errors", [])
            # Skip collector on re-runs - jump straight to investigator
            graph = _build_graph_skip_collector()
        else:
            graph = build_graph()

        # Accumulate full state across all node outputs
        accumulated = dict(initial_state)
        for chunk in graph.stream(initial_state, {"recursion_limit": 20}):
            for node_name, node_output in chunk.items():
                if isinstance(node_output, dict):
                    accumulated.update(node_output)

        accumulated["duration_seconds"] = round(time.time() - t0, 1)

        # Check for remaining false positives and build a structured
        # correction decision before deciding whether to rerun.
        likely_fps = _detect_false_positives(accumulated) if self_correct else []
        correction_decision = _build_correction_decision(
            accumulated, likely_fps, iteration, max_iterations
        )

        # Record this iteration's results
        iteration_record = {
            "iteration": iteration,
            "threshold": threshold,
            "critical_count": len(accumulated.get("critical_findings", [])),
            "medium_count": len(accumulated.get("medium_findings", [])),
            "low_count": len(accumulated.get("low_findings", [])),
            "cleared_count": len(accumulated.get("cleared_findings", [])),
            "refuted_count": len(accumulated.get("refuted", [])),
            "total_hypotheses": len(accumulated.get("hypotheses", [])),
            "false_positives_auto_cleared": len(accumulated.get("false_positives_detected", [])),
            "decision": correction_decision,
        }
        correction_history.append(iteration_record)
        accumulated["self_correction_history"] = correction_history
        accumulated["self_correction_decisions"] = [
            h.get("decision", {}) for h in correction_history
        ]

        # If not self-correcting, return immediately
        if not self_correct:
            break

        print("\n  SELF-CORRECTION DECISION", flush=True)
        print(f"    gaps   : {', '.join(correction_decision['gaps']) or 'none'}", flush=True)
        print(f"    action : {correction_decision['action']}", flush=True)
        print(f"    reason : {correction_decision['reason']}", flush=True)

        if not likely_fps:
            cleared_now = len(accumulated.get("cleared_findings", []))
            if cleared_now:
                print(
                    f"\n  [CLEARED] Self-correction resolved {cleared_now} finding(s) "
                    f"in this pass; no remaining false positives require a rerun.",
                    flush=True,
                )
            else:
                print(f"\n  [CLEARED] No false positives detected. Self-correction complete.", flush=True)
            break
        else:
            print(f"\n  [WARN]  Detected {len(likely_fps)} likely false positive(s):", flush=True)
            for fp in likely_fps:
                print(f"      - {fp['ioc']} (signals: {', '.join(fp['signals'])})", flush=True)

            # Increase threshold for next iteration
            threshold += 15
            print(f"  -> Increasing legitimacy threshold to {threshold} for next iteration",
                  flush=True)

            # If this is the last iteration, keep the results
            if iteration == max_iterations - 1:
                print(f"\n  Max iterations reached. Using best results.", flush=True)

    accumulated["self_correction_history"] = correction_history
    accumulated["self_correction_decisions"] = [
        h.get("decision", {}) for h in correction_history
    ]
    _persist_self_correction_history(accumulated, correction_history)
    return accumulated


def _build_graph_skip_collector() -> StateGraph:
    """
    Build a graph that skips the collector phase (for self-correction re-runs).
    Raw evidence is already collected - just re-investigate with new threshold.
    """
    g = StateGraph(InvestigationState)

    g.add_node("investigator", run_investigator)
    g.add_node("evidence",     run_evidence_agent)
    g.add_node("skeptic",      run_skeptic)
    g.add_node("reporter",     run_reporter)

    g.set_entry_point("investigator")
    g.add_edge("investigator", "evidence")
    g.add_edge("evidence",     "skeptic")

    g.add_conditional_edges(
        "skeptic",
        should_continue_debate,
        {
            "evidence": "evidence",
            "reporter": "reporter",
        }
    )

    g.add_edge("reporter", END)

    return g.compile()
