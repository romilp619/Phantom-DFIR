"""
PHANTOM DFIR — LangGraph Orchestrator
Wires all agents into a StateGraph with conditional edges.

Flow:
  collector → investigator → evidence → skeptic
                                  ↑           |
                                  └── (loop) ─┘
                                              |
                                           reporter
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


def run_investigation(filepath: str) -> dict:
    """
    Run the full PHANTOM DFIR investigation on the given memory image.
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
        "reasoning_log":     [],
    }

    graph = build_graph()

    # Accumulate full state across all node outputs
    accumulated = dict(initial_state)
    for chunk in graph.stream(initial_state, {"recursion_limit": 20}):
        for node_name, node_output in chunk.items():
            if isinstance(node_output, dict):
                accumulated.update(node_output)

    accumulated["duration_seconds"] = round(time.time() - t0, 1)
    return accumulated
