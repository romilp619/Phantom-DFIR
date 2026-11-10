"""Baseline measurement: run the upstream verification layer over the red-team set.

The point of this module is what it does NOT do. It does not reimplement the
decision logic. It builds the smallest state `run_skeptic` accepts, calls the real
function, and reads the confidence it produced. If the harness ever silently
diverged from upstream, these numbers would be worthless.

It also runs the same rows under several LLM stand-ins. If the output is identical
whether the model refutes everything, confirms everything, emits garbage, or is
absent entirely, then the model is not participating in the decision.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(os.path.dirname(HERE))
if PKG_ROOT not in sys.path:
    sys.path.insert(0, PKG_ROOT)

from phantom_ai_safety.evaluation.metrics import (  # noqa: E402
    CONFIDENCE_TO_COARSE,
    Outcome,
    per_family,
    score_outcomes,
)
from phantom_ai_safety.harness import env  # noqa: E402
from phantom_ai_safety.red_team.rows import EvalRow, build_eval_set, summarize  # noqa: E402

STRATEGIES = ("no_llm", "echo_count", "always_confirm", "always_refute", "garbage")


def make_hypothesis(row: EvalRow) -> dict:
    """The hypothesis object shape that `run_skeptic` expects (see state.py:55)."""
    return {
        "id": row.row_id,
        "ioc": row.claimed_ioc,
        "claim": row.claim_text,
        "attack_phase": "Unknown",
        "verified_sources": list(row.verified_sources),
        "raw_evidence_quote": row.presented_evidence[0].text if row.presented_evidence else "",
        "skeptic_challenges": [],
        "confidence": None,
    }


def make_state(row: EvalRow) -> dict:
    return {
        "hypotheses": [make_hypothesis(row)],
        "skeptic_round": 0,
        "reasoning_log": [],
        "cleared_findings": [],
        "filepath": "synthetic_evidence.img",
        "critical_findings": [],
        "medium_findings": [],
        "low_findings": [],
    }


def run_baseline(rows: list[EvalRow], strategy: str, verbose: bool = False) -> list[Outcome]:
    """Drive the real `run_skeptic` once per row under one LLM strategy."""
    skeptic = env.load_skeptic("none" if strategy == "no_llm" else strategy)

    outcomes: list[Outcome] = []
    for row in rows:
        state = make_state(row)
        if verbose:
            print(f"  [{row.row_id}] sources={len(row.verified_sources)} "
                  f"distinct_artifacts={row.distinct_artifacts} gold={row.gold}", flush=True)
        out = skeptic.run_skeptic(state)

        hyp = out["hypotheses"][0]
        confidence = hyp.get("confidence") or "UNVERIFIED"
        verdict = CONFIDENCE_TO_COARSE.get(confidence, "NEEDS_MORE")

        # The upstream pipeline has no per-claim citation mechanism, so nothing is
        # ever cited. Recorded explicitly rather than left implicit, because it
        # makes the evidence-fidelity gate trivially satisfied for the baseline.
        cited: list[str] = []

        outcomes.append(
            Outcome(
                row_id=row.row_id,
                family=row.family,
                is_attack=row.is_attack,
                gold=row.gold,
                confidence=confidence,
                verdict=verdict,
                correct=(verdict == row.gold),
                cited=cited,
                presented=[e.evidence_id for e in row.presented_evidence],
            )
        )
    return outcomes


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure the upstream verification layer")
    ap.add_argument("--per-family", type=int, default=50, help="rows per family (6 families)")
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", default=None, help="write full results JSON here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.quiet:
        sys.stdout = open(os.devnull, "w")

    rows = build_eval_set(per_family=args.per_family, seed=args.seed)

    # Keep the real stdout for the report even in quiet mode.
    real_stdout = sys.__stdout__

    def print(*parts, **_kw):  # noqa: A001 - deliberately shadows builtins
        """Report printer that survives --quiet and accepts zero arguments."""
        real_stdout.write(" ".join(str(p) for p in parts) + "\n")

    print("=" * 72 + "\nBASELINE: upstream PHANTOM verification layer\n" + "=" * 72 + "\n")
    print(f"Evaluation set: {json.dumps(summarize(rows))}\n")
    print(f"Source digest: {env.describe().get('source_digest_sha256')}\n")

    results: dict = {
        "conditions": {},
        "eval_set": summarize(rows),
        "environment": env.describe(),
        "seed": args.seed,
        "per_family": args.per_family,
    }

    all_outcomes: dict[str, list[Outcome]] = {}

    for strategy in STRATEGIES:
        outcomes = run_baseline(rows, strategy)
        all_outcomes[strategy] = outcomes
        overall = score_outcomes(outcomes)
        results["conditions"][strategy] = {
            "overall": overall,
            "per_family": per_family(outcomes),
        }

        print("-" * 72)
        print(f"LLM strategy: {strategy}")
        print("-" * 72)
        print(f"  accuracy                 {overall['accuracy']:.3f}"
              f"  95% CI [{overall['accuracy_ci'][0]:.3f}, {overall['accuracy_ci'][1]:.3f}]")
        fcr = overall["false_confirm_rate"]
        print(f"  false-confirm rate       {fcr:.3f}" if fcr is not None else
              "  false-confirm rate       n/a (no CONFIRM outputs)")
        asr = overall["attack_success_rate"]
        print(f"  attack success rate      {asr:.3f}" if asr is not None else
              "  attack success rate      n/a")
        dmr = overall["dangerous_miss_rate"]
        print(f"  dangerous-miss rate      {dmr:.3f}" if dmr is not None else
              "  dangerous-miss rate      n/a")
        xar = overall["correct_abstention_rate"]
        print(f"  correct-abstention rate  {xar:.3f}" if xar is not None else
              "  correct-abstention rate  n/a")
        cr = overall["capability_retention"]
        print(f"  capability retention     {cr:.3f}" if cr is not None else
              "  capability retention     n/a")
        print(f"  evidence-fidelity viol.  {overall['evidence_fidelity_violations']:.3f}"
              "  (trivially 0: the baseline never cites evidence)")
        print()

    # Invariance check: is the output the same no matter what the model says?
    print("=" * 72 + "\nINVARIANCE: does the model's contribution change any row?\n" + "=" * 72 + "\n")
    reference = [(o.row_id, o.confidence) for o in all_outcomes["no_llm"]]
    invariance = {}
    for strategy, outcomes in all_outcomes.items():
        current = [(o.row_id, o.confidence) for o in outcomes]
        diffs = [
            {"row_id": a[0], "no_llm": a[1], "this": b[1]}
            for a, b in zip(reference, current) if a != b
        ]
        invariance[strategy] = {"changed_rows": len(diffs), "examples": diffs[:5]}
        verdict_line = "identical" if not diffs else f"{len(diffs)} rows differ"
        print(f"  {strategy:16s} -> {verdict_line}")

    results["invariance"] = invariance

    identical = all(v["changed_rows"] == 0 for v in invariance.values())
    print()
    if identical:
        print("  RESULT: identical under every LLM strategy, including no LLM at all.")
        print("  The Skeptic's model contributes no decision authority on this path.")
    else:
        print("  RESULT: the model DOES change outputs; the D1 finding needs revision.")

    results["llm_has_authority"] = not identical

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=str)
        print(f"\nWrote {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())