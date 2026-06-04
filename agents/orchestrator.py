"""
PHANTOM DFIR — LangGraph Orchestrator v2.0
Wires all agents into a StateGraph with conditional edges.
Includes self-correction loop that retries with stricter thresholds
when false positives are detected.

Flow:
  collector → investigator → evidence → skeptic
                                   ↑           |
                                   └── (loop) ─┘
                                               |
                                            reporter

Self-correction:
  If false positives detected → increase legitimacy threshold → re-run
"""
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

    # Linear flow: collect → investigate → first evidence pass → skeptic
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
    Uses behavioral signals — NOT hardcoded process names.

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

        # If 2+ false positive signals → likely false positive
        if len(signals) >= 2:
            likely_fps.append({
                "hypothesis": h,
                "signals": signals,
                "ioc": h.get("ioc", ""),
            })

    return likely_fps


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
╔══════════════════════════════════════════════════════════════╗
║            P H A N T O M   D F I R                          ║
║  Parallel Hypothesis Analysis with Multi-agent Threat        ║
║  Hunting Overlay Network                                     ║
║                                                              ║
║  World's first adversarial self-verifying DFIR agent         ║
║  Find Evil! Hackathon 2026  |  LangGraph + Ollama            ║
╚══════════════════════════════════════════════════════════════╝
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
            print(f"  SELF-CORRECTION — Iteration {iteration + 1}/{max_iterations}", flush=True)
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
            "reasoning_log":     [],
        }

        # On subsequent iterations, reuse the raw evidence from iteration 0
        # (no need to re-collect — that's the expensive part)
        if iteration > 0 and "raw_evidence" in accumulated:
            initial_state["raw_evidence"] = accumulated["raw_evidence"]
            initial_state["os_type"] = accumulated.get("os_type", "unknown")
            initial_state["collection_errors"] = accumulated.get("collection_errors", [])
            # Skip collector on re-runs — jump straight to investigator
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

        # Record this iteration's results
        iteration_record = {
            "iteration": iteration,
            "threshold": threshold,
            "critical_count": len(accumulated.get("critical_findings", [])),
            "cleared_count": len(accumulated.get("cleared_findings", [])),
            "total_hypotheses": len(accumulated.get("hypotheses", [])),
            "false_positives_auto_cleared": len(accumulated.get("false_positives_detected", [])),
        }
        correction_history.append(iteration_record)

        # If not self-correcting, return immediately
        if not self_correct:
            break

        # Check for remaining false positives
        likely_fps = _detect_false_positives(accumulated)

        if not likely_fps:
            print(f"\n  ✅ No false positives detected. Self-correction complete.", flush=True)
            break
        else:
            print(f"\n  ⚠️  Detected {len(likely_fps)} likely false positive(s):", flush=True)
            for fp in likely_fps:
                print(f"      - {fp['ioc']} (signals: {', '.join(fp['signals'])})", flush=True)

            # Increase threshold for next iteration
            threshold += 15
            print(f"  → Increasing legitimacy threshold to {threshold} for next iteration",
                  flush=True)

            # If this is the last iteration, keep the results
            if iteration == max_iterations - 1:
                print(f"\n  Max iterations reached. Using best results.", flush=True)

    accumulated["self_correction_history"] = correction_history
    return accumulated


def _build_graph_skip_collector() -> StateGraph:
    """
    Build a graph that skips the collector phase (for self-correction re-runs).
    Raw evidence is already collected — just re-investigate with new threshold.
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
