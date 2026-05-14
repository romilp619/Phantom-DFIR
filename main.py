#!/usr/bin/env python3
"""
PHANTOM DFIR — Main Entry Point
Usage: python3 main.py -f /path/to/memory.img [--no-llm] [--model MODEL]
"""
import argparse
import os
import sys

# ── Ensure phantom-dfir dir is in path ───────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config  # noqa: F401 — must import before agents


def parse_args():
    p = argparse.ArgumentParser(
        description="PHANTOM DFIR — Adversarial Self-Verifying DFIR Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -f base-admin-memory.img
  python3 main.py -f memory.raw --model qwen2.5:14b
  python3 main.py -f memory.img --no-llm     # rule-based only (faster)
        """
    )
    p.add_argument("-f", "--file",    required=True, help="Path to memory image")
    p.add_argument("--model",         default=config.OLLAMA_MODEL,
                   help=f"Ollama model to use (default: {config.OLLAMA_MODEL})")
    p.add_argument("--ollama-url",    default=config.OLLAMA_BASE_URL,
                   help="Ollama base URL (default: http://localhost:11434)")
    p.add_argument("--no-llm",        action="store_true",
                   help="Skip LLM — use rule-based investigator and skeptic only")
    p.add_argument("--vol3",          default=None,
                   help="Override path to vol (Vol3)")
    p.add_argument("--vol2",          default=None,
                   help="Override path to vol2 (Vol2)")
    p.add_argument("--output-dir",    default=os.path.expanduser("~"),
                   help="Directory to write reports (default: ~/)")
    return p.parse_args()


def main():
    args = parse_args()

    # Validate target file
    if not os.path.exists(args.file):
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)

    # Apply CLI overrides to config
    config.OLLAMA_MODEL    = args.model
    config.OLLAMA_BASE_URL = args.ollama_url
    config.REPORT_DIR      = args.output_dir
    if args.vol3:
        config.VOL3_CMD = args.vol3
    if args.vol2:
        config.VOL2_CMD = args.vol2

    if args.no_llm:
        # Monkey-patch LLM agents to skip LLM calls
        import agents.investigator as inv
        import agents.skeptic      as sk
        inv.llm = None
        sk.llm  = None
        print("[*] --no-llm mode: using rule-based investigator and skeptic", flush=True)

    # Run investigation
    from agents.orchestrator import run_investigation
    final_state = run_investigation(args.file)

    if not final_state:
        print("[ERROR] Investigation returned empty state.")
        sys.exit(1)

    print(f"\n[✓] Reports saved to: {args.output_dir}")
    print(f"    JSON: {final_state.get('report_json_path','')}")
    print(f"    MD:   {final_state.get('report_md_path','')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
