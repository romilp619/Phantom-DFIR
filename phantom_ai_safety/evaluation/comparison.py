"""Before/after comparison: upstream verification layer versus the grounded repair.

Writes per-row records for both conditions, so a reader can re-score the run from
the published data rather than trusting the summary. Paired by row id, and tested
with exact McNemar because the same rows are measured twice.

Also runs the evidence-injection scanner across every row's evidence, which is a
separate capability from the verdict change and is reported separately.
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

from phantom_ai_safety.evaluation.baseline import run_baseline  # noqa: E402
from phantom_ai_safety.evaluation.metrics import (  # noqa: E402
    Outcome,
    mcnemar_exact,
    per_family,
    score_outcomes,
)
from phantom_ai_safety.evidence_scanner.scanner import scan_evidence, summarize as scan_summary  # noqa: E402
from phantom_ai_safety.grounding.verifier import verify  # noqa: E402
from phantom_ai_safety.harness import env  # noqa: E402
from phantom_ai_safety.red_team.rows import build_eval_set, summarize  # noqa: E402


def run_improved(rows) -> list[Outcome]:
    """Score the same rows with the grounded verifier."""
    outcomes: list[Outcome] = []
    for row in rows:
        v = verify(row.claim_text, row.claimed_ioc, row.presented_evidence)
        presented_ids = [e.evidence_id for e in row.presented_evidence]
        outcomes.append(
            Outcome(
                row_id=row.row_id,
                family=row.family,
                is_attack=row.is_attack,
                gold=row.gold,
                confidence=v.verdict,
                verdict=v.verdict,
                correct=(v.verdict == row.gold),
                cited=list(v.citations),
                presented=presented_ids,
            )
        )
    return outcomes


def citation_coverage(outcomes: list[Outcome]) -> dict:
    """Does the repaired system actually cite on the findings it confirms?

    Guards against a repair that passes the evidence-fidelity gate by never citing.
    """
    confirmed = [o for o in outcomes if o.verdict == "CONFIRMED"]
    if not confirmed:
        return {"confirmed_rows": 0, "with_citation": 0, "coverage": None}
    with_cite = [o for o in confirmed if o.cited]
    return {
        "confirmed_rows": len(confirmed),
        "with_citation": len(with_cite),
        "coverage": len(with_cite) / len(confirmed),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-family", type=int, default=50)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", default="results/comparison.json")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.quiet:
        sys.stdout = open(os.devnull, "w")
    real = sys.__stdout__

    def say(*parts, **_kw):
        real.write(" ".join(str(p) for p in parts) + "\n")

    rows = build_eval_set(per_family=args.per_family, seed=args.seed)
    row_by_id = {r.row_id: r for r in rows}

    say("=" * 78)
    say("BEFORE / AFTER COMPARISON")
    say("=" * 78)
    say(f"eval set: {json.dumps(summarize(rows))}")
    say(f"source digest: {env.describe().get('source_digest_sha256')}")
    say("")

    before = run_baseline(rows, "no_llm")
    after = run_improved(rows)

    before_metrics = score_outcomes(before)
    after_metrics = score_outcomes(after)

    # Paired correctness for exact McNemar.
    b_map = {o.row_id: o.correct for o in before}
    a_map = {o.row_id: o.correct for o in after}
    b_wrong_a_right = sum(1 for k in b_map if not b_map[k] and a_map.get(k))
    b_right_a_wrong = sum(1 for k in b_map if b_map[k] and not a_map.get(k, False))
    p_value = mcnemar_exact(b_wrong_a_right, b_right_a_wrong)

    scan = scan_evidence([(e.evidence_id, e.text) for r in rows for e in r.presented_evidence])
    scan_stats = scan_summary(scan)

    comparison = {
        "eval_set": summarize(rows),
        "environment": env.describe(),
        "seed": args.seed,
        "per_family": args.per_family,
        "conditions": {
            "before_upstream": {"overall": before_metrics, "per_family": per_family(before)},
            "after_grounded_repair": {"overall": after_metrics, "per_family": per_family(after)},
        },
        "mcnemar": {
            "baseline_wrong_after_right": b_wrong_a_right,
            "baseline_right_after_wrong": b_right_a_wrong,
            "exact_p_two_sided": p_value,
        },
        "citation_coverage_after": citation_coverage(after),
        "citation_coverage_before": citation_coverage(before),
        "injection_scanner": scan_stats,
        "rows": {
            "before": [asdict(o) for o in before],
            "after": [asdict(o) for o in after],
            "gold": {r.row_id: {"gold": r.gold, "family": r.family, "is_attack": r.is_attack,
                                "distinct_artifacts": r.distinct_artifacts,
                                "source_keys": len(r.verified_sources)}
                     for r in rows},
        },
    }

    def line(label, key, pct=True):
        b, a = before_metrics.get(key), after_metrics.get(key)
        fb = "n/a" if b is None else (f"{b:.3f}")
        fa = "n/a" if a is None else (f"{a:.3f}")
        delta = "" if (b is None or a is None) else f"   delta {a - b:+.3f}"
        say(f"  {label:26s} before {fb:>7s}   after {fa:>7s}{delta}")

    say("-" * 78)
    say(f"{'metric':26s} {'before':>13s}   {'after':>7s}")
    say("-" * 78)
    line("accuracy", "accuracy")
    line("false-confirm rate", "false_confirm_rate")
    line("attack success rate", "attack_success_rate")
    line("dangerous-miss rate", "dangerous_miss_rate")
    line("correct-abstention rate", "correct_abstention_rate")
    line("capability retention", "capability_retention")
    say(f"  {'evidence-fidelity viol.':26s} before {before_metrics['evidence_fidelity_violations']:.3f}"
        f"   after {after_metrics['evidence_fidelity_violations']:.3f}")

    say("")
    say("-" * 78)
    say("Per family")
    say("-" * 78)
    say(f"{'family':26s}{'acc b/a':>16s}{'ASR b/a':>16s}{'FCR b/a':>16s}")
    fams = sorted({o.family for o in before})
    for fam in fams:
        bm = comparison["conditions"]["before_upstream"]["per_family"][fam]
        am = comparison["conditions"]["after_grounded_repair"]["per_family"][fam]
        def pair(kk):
            bb = bm.get(kk); aa = am.get(kk)
            f = lambda v: "n/a" if v is None else f"{v:.2f}"
            return f"{f(bb)}/{f(aa)}"
        say(f"{fam:26s}{pair('accuracy'):>16s}{pair('attack_success_rate'):>16s}{pair('false_confirm_rate'):>16s}")

    say("")
    say("-" * 78)
    say("Statistics and gates")
    say("-" * 78)
    say(f"  McNemar exact (paired): baseline-wrong/after-right {b_wrong_a_right}, "
        f"baseline-right/after-wrong {b_right_a_wrong}, p = {p_value:.3g}")
    cc = comparison["citation_coverage_after"]
    say(f"  citation coverage (after): {cc['with_citation']}/{cc['confirmed_rows']} "
        f"confirmed rows cite evidence = {cc['coverage']}")
    cb = comparison["citation_coverage_before"]
    say(f"  citation coverage (before): {cb['with_citation']}/{cb['confirmed_rows']} "
        f"confirmed rows cite evidence = {cb['coverage']}")
    say(f"  injection scanner: {json.dumps(scan_stats)}")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(comparison, fh, indent=2, default=str)
    say("")
    say(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())