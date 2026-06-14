#!/usr/bin/env python3
"""
PHANTOM DFIR - Main Entry Point
Usage: python3 main.py -f /path/to/memory.img [--no-llm] [--model MODEL]
       python3 main.py -f /path/to/memory.img --provider claude --api-key sk-...
       python3 main.py -f /path/to/memory.img --self-correct
       python3 main.py -f /path/to/memory.img --self-correct --max-iterations 5
"""
import argparse
import os
import sys

# -- Ensure phantom-dfir dir is in path ---------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: F401 - must import before agents


def parse_args():
    p = argparse.ArgumentParser(
        description="PHANTOM DFIR - Adversarial Self-Verifying DFIR Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -f base-admin-memory.img
  python3 main.py -f memory.raw --model qwen2.5:14b
  python3 main.py -f memory.img --no-llm     # rule-based only (faster)
  python3 main.py -f memory.img --self-correct              # auto-fix false positives
  python3 main.py -f memory.img --self-correct --max-iterations 5
  python3 main.py -f memory.img --self-correct --threshold 60

  # Use Claude instead of Ollama:
  python3 main.py -f memory.img --provider claude --api-key sk-ant-...

  # Use OpenAI:
  OPENAI_API_KEY=sk-... python3 main.py -f memory.img --provider openai

  # Use Groq (fast cloud inference):
  python3 main.py -f memory.img --provider groq --api-key gsk_...
        """
    )
    p.add_argument("-f", "--file",    required=True, help="Path to memory image")
    p.add_argument("--model",         default=config.OLLAMA_MODEL,
                   help=f"Model name (default: {config.OLLAMA_MODEL})")
    p.add_argument("--ollama-url",    default=config.OLLAMA_BASE_URL,
                   help="Ollama base URL (default: http://localhost:11434)")
    p.add_argument("--no-llm",        action="store_true",
                   help="Skip LLM - use rule-based investigator and skeptic only")

    # LLM provider flags
    p.add_argument("--provider",      default=config.LLM_PROVIDER,
                   choices=["ollama", "claude", "openai", "groq"],
                   help="LLM provider (default: ollama)")
    p.add_argument("--api-key",       default=None,
                   help="API key for cloud LLM provider (Claude/OpenAI/Groq)")

    p.add_argument("--vol3",          default=None,
                   help="Override path to vol (Vol3)")
    p.add_argument("--vol2",          default=None,
                   help="Override path to vol2 (Vol2)")
    p.add_argument("--output-dir",    default=os.path.expanduser("~"),
                   help="Directory to write reports (default: ~/)")

    # Self-correction flags
    p.add_argument("--self-correct",  action="store_true",
                   help="Enable self-correction loop - retries with stricter "
                        "thresholds when false positives detected")
    p.add_argument("--max-iterations", type=int, default=3,
                   help="Max self-correction iterations (default: 3)")
    p.add_argument("--threshold",     type=int, default=50,
                   help="Initial legitimacy threshold 0-100 (default: 50, "
                        "higher = stricter filtering)")
    return p.parse_args()


def main():
    args = parse_args()

    # Validate target file
    if not os.path.exists(args.file):
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)

    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as e:
        print(f"[ERROR] Could not create output directory {args.output_dir}: {e}")
        sys.exit(1)

    # Apply CLI overrides to config
    config.OLLAMA_MODEL    = args.model
    config.OLLAMA_BASE_URL = args.ollama_url
    config.REPORT_DIR      = args.output_dir
    config.LLM_PROVIDER    = args.provider
    if args.api_key:
        config.LLM_API_KEY = args.api_key
    if args.vol3:
        config.VOL3_CMD = args.vol3
    if args.vol2:
        config.VOL2_CMD = args.vol2

    # Show provider info
    if args.provider != "ollama":
        print(f"[*] LLM provider: {args.provider} | model: {args.model}", flush=True)

    if args.no_llm:
        # Monkey-patch LLM agents to skip LLM calls
        import agents.investigator as inv
        import agents.skeptic      as sk
        inv.llm = None
        sk.llm  = None
        print("[*] --no-llm mode: using rule-based investigator and skeptic", flush=True)

    if args.self_correct:
        print(f"[*] Self-correction enabled: max {args.max_iterations} iterations, "
              f"initial threshold={args.threshold}", flush=True)

    # Run investigation
    from agents.orchestrator import run_investigation
    final_state = run_investigation(
        args.file,
        self_correct=args.self_correct,
        max_iterations=args.max_iterations,
        initial_threshold=args.threshold,
    )

    if not final_state:
        print("[ERROR] Investigation returned empty state.")
        sys.exit(1)

    # Print self-correction summary if applicable
    history = final_state.get("self_correction_history", [])
    if args.self_correct and history:
        print(f"\n{'='*60}")
        print(f"  SELF-CORRECTION SUMMARY")
        print(f"{'='*60}")
        for h in history:
            decision = h.get("decision", {})
            gaps = ", ".join(decision.get("gaps", [])) or "none"
            print(f"  Iteration {h['iteration']+1}: threshold={h['threshold']}, "
                  f"critical={h['critical_count']}, cleared={h['cleared_count']}", flush=True)
            print(f"    gaps   : {gaps}", flush=True)
            print(f"    action : {decision.get('action', 'unknown')}", flush=True)
        first = history[0]
        last = history[-1]
        reduced = first["critical_count"] - last["critical_count"]
        if len(history) == 1 and last.get("cleared_count", 0) > 0:
            print(
                f"\n  -> Resolved {last['cleared_count']} finding(s) in the first pass; "
                "no rerun was needed.",
                flush=True,
            )
        elif reduced > 0:
            print(f"\n  -> Reduced {reduced} false positive(s) through self-correction", flush=True)
        else:
            print("\n  -> No additional correction pass was required.", flush=True)

    # Print false positives cleared
    fps = final_state.get("false_positives_detected", [])
    if fps:
        print(f"\n  Legitimacy engine auto-cleared {len(fps)} process(es):")
        for fp in fps:
            score = fp.get("legitimacy_score", "?")
            print(f"    [CLEARED] {fp.get('ioc', '?')} (score: {score}/100)")

    print(f"\n[OK] Reports saved to: {args.output_dir}")
    print(f"    JSON: {final_state.get('report_json_path','')}")
    print(f"    MD:   {final_state.get('report_md_path','')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
