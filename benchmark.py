#!/usr/bin/env python3
"""
PHANTOM DFIR — Accuracy Benchmarking Framework v1.0

Runs PHANTOM against a memory image with KNOWN ground truth,
then scores accuracy, false positive rate, and hallucination frequency.

Usage:
  python3 benchmark.py -f base-admin-memory.img --ground-truth ground_truth.json
  python3 benchmark.py -f memory.img --ground-truth gt.json --model qwen2.5:14b

Ground Truth JSON format:
{
  "expected_malicious": [
    {"ioc": "subject_srv.exe", "attack_phase": "Persistence", "mitre": "T1543.003"},
    {"ioc": "172.16.4.10",     "attack_phase": "C2",          "mitre": "T1071.001"},
    {"ioc": "putty.exe",       "attack_phase": "LateralMovement", "mitre": "T1021.004"}
  ],
  "expected_benign": [
    {"ioc": "ruby.exe", "reason": "Puppet Labs legitimate installation"},
    {"ioc": "vmtoolsd.exe", "reason": "VMware Tools"}
  ],
  "expected_network": ["172.16.4.10"],
  "case_description": "Windows 10 compromised via Metasploit + lateral SSH movement"
}
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_ground_truth(path: str) -> dict:
    """Load and validate ground truth JSON."""
    with open(path) as f:
        gt = json.load(f)
    required = ["expected_malicious", "expected_benign"]
    for key in required:
        if key not in gt:
            print(f"[ERROR] Ground truth missing '{key}' field")
            sys.exit(1)
    return gt


def run_phantom(filepath: str, model: str = None) -> dict:
    """Run PHANTOM investigation and return final state."""
    import config
    if model:
        config.OLLAMA_MODEL = model

    from agents.orchestrator import run_investigation
    return run_investigation(filepath)


def score_results(state: dict, ground_truth: dict) -> dict:
    """
    Score PHANTOM's output against known ground truth.
    Returns detailed accuracy metrics.
    """
    gt_malicious = ground_truth.get("expected_malicious", [])
    gt_benign    = ground_truth.get("expected_benign", [])

    # PHANTOM's findings
    critical = state.get("critical_findings", [])
    medium   = state.get("medium_findings", [])
    low      = state.get("low_findings", [])
    cleared  = state.get("cleared_findings", [])
    refuted  = state.get("refuted", [])
    all_flagged = critical + medium + low  # everything PHANTOM flagged as malicious

    # ── True Positives: PHANTOM flagged something that IS in ground truth ────
    tp = []
    fn = []  # False Negatives: in ground truth but PHANTOM missed
    for expected in gt_malicious:
        ioc = expected["ioc"].lower()
        found = False
        for f in all_flagged:
            if ioc in f.get("ioc", "").lower() or ioc in f.get("claim", "").lower():
                tp.append({
                    "expected_ioc": expected["ioc"],
                    "phantom_id":   f.get("id", "?"),
                    "phantom_conf": f.get("confidence", "?"),
                    "mitre_match":  expected.get("mitre", "?") in str(f.get("mitre_ids", [])),
                })
                found = True
                break
        if not found:
            fn.append(expected)

    # ── False Positives: PHANTOM flagged something NOT in ground truth ────
    gt_iocs = {e["ioc"].lower() for e in gt_malicious}
    gt_benign_iocs = {e["ioc"].lower() for e in gt_benign}
    fp = []
    for f in all_flagged:
        f_ioc = f.get("ioc", "").lower()
        is_tp = any(gt_ioc in f_ioc or f_ioc in gt_ioc for gt_ioc in gt_iocs)
        if not is_tp:
            fp.append({
                "phantom_id":   f.get("id", "?"),
                "ioc":          f.get("ioc", "?"),
                "confidence":   f.get("confidence", "?"),
                "claim":        f.get("claim", "?")[:80],
            })

    # ── Correctly Cleared: PHANTOM cleared something that IS benign ──────
    correctly_cleared = []
    missed_benign = []  # PHANTOM flagged a benign process as malicious
    for expected in gt_benign:
        ioc = expected["ioc"].lower()
        # Check if it was cleared
        was_cleared = any(ioc in c.get("ioc", "").lower() or ioc in c.get("claim", "").lower()
                         for c in cleared)
        # Check if it was incorrectly flagged
        was_flagged = any(ioc in f.get("ioc", "").lower() or ioc in f.get("claim", "").lower()
                         for f in all_flagged)
        if was_cleared:
            correctly_cleared.append(expected["ioc"])
        elif was_flagged:
            missed_benign.append({
                "ioc": expected["ioc"],
                "reason": expected.get("reason", ""),
                "should_be": "CLEARED (benign)",
            })

    # ── Hallucination Rate ──────────────────────────────────────────────
    total_findings = len(all_flagged) + len(cleared)
    hallucination_count = len(refuted)

    # ── Metrics ──────────────────────────────────────────────────────────
    precision = len(tp) / max(len(all_flagged), 1)
    recall    = len(tp) / max(len(gt_malicious), 1)
    f1        = 2 * (precision * recall) / max(precision + recall, 0.001)
    fp_rate   = len(fp) / max(len(all_flagged), 1)
    hallucination_rate = hallucination_count / max(total_findings, 1)

    return {
        "metrics": {
            "precision":          round(precision, 3),
            "recall":             round(recall, 3),
            "f1_score":           round(f1, 3),
            "false_positive_rate": round(fp_rate, 3),
            "hallucination_rate": round(hallucination_rate, 3),
            "true_positives":     len(tp),
            "false_positives":    len(fp),
            "false_negatives":    len(fn),
            "correctly_cleared":  len(correctly_cleared),
            "hallucinations_caught": hallucination_count,
            "total_findings":     total_findings,
        },
        "true_positives":     tp,
        "false_positives":    fp,
        "false_negatives":    fn,
        "correctly_cleared":  correctly_cleared,
        "missed_benign":      missed_benign,
        "ground_truth_coverage": {
            "malicious_detected": f"{len(tp)}/{len(gt_malicious)}",
            "benign_cleared":     f"{len(correctly_cleared)}/{len(gt_benign)}",
        },
    }


def print_scorecard(scores: dict, duration: float):
    """Print a human-readable accuracy scorecard."""
    m = scores["metrics"]
    SEP = "═" * 55

    print(f"\n{SEP}")
    print("  PHANTOM DFIR — ACCURACY SCORECARD")
    print(SEP)

    print(f"\n  ┌─────────────────────────┬──────────┐")
    print(f"  │ Metric                  │ Score    │")
    print(f"  ├─────────────────────────┼──────────┤")
    print(f"  │ Precision               │ {m['precision']:.1%}    │")
    print(f"  │ Recall                  │ {m['recall']:.1%}    │")
    print(f"  │ F1 Score                │ {m['f1_score']:.1%}    │")
    print(f"  │ False Positive Rate     │ {m['false_positive_rate']:.1%}    │")
    print(f"  │ Hallucination Rate      │ {m['hallucination_rate']:.1%}    │")
    print(f"  ├─────────────────────────┼──────────┤")
    print(f"  │ True Positives          │ {m['true_positives']:>8} │")
    print(f"  │ False Positives         │ {m['false_positives']:>8} │")
    print(f"  │ False Negatives         │ {m['false_negatives']:>8} │")
    print(f"  │ Correctly Cleared       │ {m['correctly_cleared']:>8} │")
    print(f"  │ Hallucinations Caught   │ {m['hallucinations_caught']:>8} │")
    print(f"  └─────────────────────────┴──────────┘")

    cov = scores["ground_truth_coverage"]
    print(f"\n  Coverage: {cov['malicious_detected']} malicious detected, "
          f"{cov['benign_cleared']} benign cleared")
    print(f"  Duration: {duration:.1f}s")

    # Grade
    f1 = m["f1_score"]
    if f1 >= 0.9:
        grade = "A+ — OUTSTANDING"
    elif f1 >= 0.8:
        grade = "A  — EXCELLENT"
    elif f1 >= 0.7:
        grade = "B  — GOOD"
    elif f1 >= 0.5:
        grade = "C  — NEEDS IMPROVEMENT"
    else:
        grade = "F  — FAILING"

    print(f"\n  GRADE: {grade} (F1={f1:.1%})")

    if scores["false_negatives"]:
        print(f"\n  ⚠️  MISSED ({len(scores['false_negatives'])}):")
        for fn in scores["false_negatives"]:
            print(f"     • {fn['ioc']} ({fn.get('attack_phase','?')})")

    if scores["false_positives"]:
        print(f"\n  ⚠️  FALSE POSITIVES ({len(scores['false_positives'])}):")
        for fp in scores["false_positives"][:5]:
            print(f"     • {fp['ioc']} ({fp['confidence']})")

    if scores["missed_benign"]:
        print(f"\n  ⚠️  BENIGN FLAGGED AS MALICIOUS ({len(scores['missed_benign'])}):")
        for mb in scores["missed_benign"]:
            print(f"     • {mb['ioc']} — should be CLEARED ({mb['reason']})")

    print(f"\n{SEP}\n")


def main():
    p = argparse.ArgumentParser(
        description="PHANTOM DFIR Accuracy Benchmarking Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-f", "--file", required=True, help="Path to memory image")
    p.add_argument("--ground-truth", required=True, help="Path to ground truth JSON")
    p.add_argument("--model", default=None, help="Ollama model override")
    p.add_argument("--output", default=None, help="Output benchmark results JSON path")
    args = p.parse_args()

    if not os.path.exists(args.file):
        print(f"[ERROR] Memory image not found: {args.file}")
        sys.exit(1)
    if not os.path.exists(args.ground_truth):
        print(f"[ERROR] Ground truth not found: {args.ground_truth}")
        sys.exit(1)

    # Load ground truth
    gt = load_ground_truth(args.ground_truth)
    print(f"[Benchmark] Ground truth: {len(gt['expected_malicious'])} malicious, "
          f"{len(gt['expected_benign'])} benign")

    # Run PHANTOM
    t0 = time.time()
    state = run_phantom(args.file, args.model)
    duration = time.time() - t0

    if not state:
        print("[ERROR] PHANTOM returned empty state")
        sys.exit(1)

    # Score
    scores = score_results(state, gt)
    scores["metadata"] = {
        "benchmark_timestamp": datetime.now().isoformat(),
        "memory_image": args.file,
        "ground_truth_file": args.ground_truth,
        "duration_seconds": round(duration, 1),
        "model": args.model or "default",
    }

    # Print scorecard
    print_scorecard(scores, duration)

    # Save results
    out_path = args.output or os.path.expanduser(
        f"~/phantom_benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(out_path, "w") as f:
        json.dump(scores, f, indent=2, default=str)
    print(f"[Benchmark] Results saved to: {out_path}")


if __name__ == "__main__":
    main()
