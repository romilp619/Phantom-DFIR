"""Build the fine-tuning set: gold-corrected targets, leak removal, CuratorKIT curation.

`data/train.jsonl` is left untouched. This script reads it and writes a separate file,
because three properties of the stored file make it unsuitable to fine-tune on as is:

  1. Targets are the rule verifier's output, not the gold label. On four families the
     stored target is CONFIRMED where gold is NEEDS_MORE or REFUTED (the three families
     the rule verifier still fails, plus `semantic_denial`, whose stored targets predate
     the verifier fix). Fine-tuning on those targets would train the model to confirm
     the attacks. Here every target whose verdict disagrees with gold is replaced by a
     gold-consistent target.

  2. Some training prompts also appear verbatim in the held-out file. Those rows are
     dropped so a held-out score cannot come from a memorised prompt.

  3. CuratorKIT's exact deduplicator hashes `instruction + output` and ignores `input`.
     With the usual alpaca projection (system -> instruction, user -> input) every row
     shares one instruction, so rows with different evidence but the same templated
     answer are removed as duplicates. On this corpus that deletes four families
     entirely. This script measures that, then projects the full prompt into
     `instruction` so the duplicate key covers the evidence.

Usage:
    python scripts/build_curated_train.py --per-family-cap 150

Exit codes: 0 success, 1 configuration/verification failure, 2 toolkit unavailable.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)
for p in (PKG_ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from phantom_ai_safety.curation.guards import (  # noqa: E402
    CurationConfigError,
    safe_clean_transforms,
    validate_config,
    verify_run,
)
from curatorkit_curate_hardened import run_curation  # noqa: E402

# Gold-consistent targets for the rows whose stored target disagrees with gold. The
# wording follows the family definitions in docs/REMAINING-FAMILIES.md and
# docs/SEMANTIC-DENIAL-FIX.md.
GOLD_TARGETS = {
    "behavioural_mention": {
        "reason": (
            "The presented artifacts describe behaviour, but none of it supports the "
            "claim: the activity they describe is benign. Behaviour that does not "
            "incriminate is not corroboration."
        ),
        "limitations": ["Incriminating behaviour may exist outside the presented evidence."],
    },
    "identity_alias": {
        "reason": (
            "The presented records are different views of one process, identified in "
            "different ways. Views of one process are one underlying artifact, below "
            "the 3 distinct behavioural artifacts required for confirmation."
        ),
        "limitations": ["Distinct artifacts may still share a single underlying cause."],
    },
    "network_contact_inflation": {
        "reason": (
            "The presented records are repeated connections to one destination. "
            "Repeated contact with a single endpoint is one behaviour, below the 3 "
            "distinct behavioural artifacts required, and does not show the endpoint "
            "is malicious."
        ),
        "limitations": ["The destination's reputation was not checked."],
    },
    "semantic_denial": {
        "reason": (
            "The presented artifacts state that the claimed activity did not occur. "
            "Evidence that denies the claim contradicts it and cannot confirm it."
        ),
        "limitations": ["Absence in the presented set is not absence in the image."],
    },
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _by_role(rec: dict) -> dict:
    return {m["role"]: m["content"] for m in rec["messages"]}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def correct_to_gold(rec: dict) -> tuple[dict, bool]:
    """Return the record with a gold-consistent target, and whether it changed."""
    roles = _by_role(rec)
    target = json.loads(roles["assistant"])
    if target["verdict"] == rec["gold"]:
        return rec, False
    template = GOLD_TARGETS.get(rec["family"])
    if template is None:
        raise CurationConfigError(
            f"{rec['id']}: target {target['verdict']} != gold {rec['gold']} in family "
            f"{rec['family']}, which has no gold-consistent target template"
        )
    fixed = {
        "verdict": rec["gold"],
        "citations": target["citations"],
        "reason": template["reason"],
        "limitations": template["limitations"],
    }
    out = dict(rec)
    out["messages"] = [
        {"role": "system", "content": roles["system"]},
        {"role": "user", "content": roles["user"]},
        {"role": "assistant", "content": json.dumps(fixed, ensure_ascii=True)},
    ]
    return out, True


def write_alpaca(rows: list[dict], path: str, full_prompt_in_instruction: bool) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for rec in rows:
            roles = _by_role(rec)
            if full_prompt_in_instruction:
                item = {"instruction": roles["system"].strip() + "\n\n" + roles["user"].strip(),
                        "input": "", "output": roles["assistant"].strip()}
            else:
                item = {"instruction": roles["system"].strip(),
                        "input": roles["user"].strip(), "output": roles["assistant"].strip()}
            item["id"] = rec["id"]
            fh.write(json.dumps(item) + "\n")


def families_of(passed, lookup: dict) -> tuple[list[dict], int]:
    """Map curated samples back to source rows by normalised prompt text."""
    matched, unmatched = [], 0
    for sample in passed:
        key = _norm((getattr(sample, "instruction", "") or "") + " "
                    + (getattr(sample, "input", "") or ""))
        rec = lookup.get(key)
        if rec is None:
            unmatched += 1
        else:
            matched.append(rec)
    return matched, unmatched


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--train", default="data/train.jsonl")
    ap.add_argument("--heldout", default="data/heldout.jsonl")
    ap.add_argument("--out", default="data/train_curated.jsonl")
    ap.add_argument("--report", default="results/curation_pipeline_report.json")
    ap.add_argument("--workdir", default="/tmp/phantom_curation_pipeline")
    ap.add_argument("--per-family-cap", type=int, default=0,
                    help="keep at most N rows per family, lowest ids first (0 = all)")
    args = ap.parse_args()

    try:
        import curatorkit
    except Exception as exc:  # noqa: BLE001
        print(f"curatorkit unavailable: {exc}", file=sys.stderr)
        return 2

    os.makedirs(args.workdir, exist_ok=True)
    source = load_jsonl(args.train)
    heldout = load_jsonl(args.heldout)
    fam_count = lambda rows: dict(sorted(collections.Counter(r["family"] for r in rows).items()))

    # ---- 1. gold-correct the targets
    corrected, changed = [], collections.Counter()
    for rec in source:
        new, was_changed = correct_to_gold(rec)
        corrected.append(new)
        if was_changed:
            changed[rec["family"]] += 1
    assert all(json.loads(_by_role(r)["assistant"])["verdict"] == r["gold"] for r in corrected)
    print(f"gold correction: {sum(changed.values())} of {len(source)} targets replaced "
          f"{dict(sorted(changed.items()))}")

    # ---- 2. drop prompts that also appear in the held-out file
    heldout_prompts = {_norm(_by_role(r)["user"]) for r in heldout}
    leaked = [r for r in corrected if _norm(_by_role(r)["user"]) in heldout_prompts]
    clean = [r for r in corrected if _norm(_by_role(r)["user"]) not in heldout_prompts]
    print(f"held-out overlap: dropped {len(leaked)} training rows {fam_count(leaked)}")

    try:
        guard = validate_config(
            format="alpaca", injection_rate=0.0, injection_types=None,
            clean_transforms=safe_clean_transforms(keep_markers=True), keep_markers=True,
        )
    except CurationConfigError as exc:
        print(f"CONFIG REJECTED: {exc}", file=sys.stderr)
        return 1

    lookup = {_norm(_by_role(r)["system"] + " " + _by_role(r)["user"]): r for r in clean}
    assert len(lookup) == len(clean), "prompts are not unique after normalisation"

    # ---- 3a. the usual projection, measured so the defect is on record
    naive_path = os.path.join(args.workdir, "alpaca_naive.jsonl")
    write_alpaca(clean, naive_path, full_prompt_in_instruction=False)
    naive_res, _ = run_curation(naive_path, "alpaca", os.path.join(args.workdir, "out_naive"),
                                "phantom_train_naive")
    naive_kept, naive_unmatched = families_of(list(naive_res.passed or []), lookup)

    # ---- 3b. full prompt in `instruction`, so the duplicate key covers the evidence
    full_path = os.path.join(args.workdir, "alpaca_full_prompt.jsonl")
    write_alpaca(clean, full_path, full_prompt_in_instruction=True)
    try:
        res, elapsed = run_curation(full_path, "alpaca", os.path.join(args.workdir, "out"),
                                    "phantom_train")
        passed, rejected = list(res.passed or []), list(res.rejected or [])
        post = verify_run(passed, rejected, expected_markers=True)
    except CurationConfigError as exc:
        print(f"POST-RUN VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 1
    kept, unmatched = families_of(passed, lookup)
    if unmatched:
        print(f"FAILED: {unmatched} curated rows could not be traced to a source row",
              file=sys.stderr)
        return 1
    print(f"curatorkit (instruction+input projection): kept {len(naive_kept)} of "
          f"{len(clean)}  {fam_count(naive_kept)}")
    print(f"curatorkit (full-prompt projection):       kept {len(kept)} of {len(clean)}")

    # ---- 4. optional per-family cap, deterministic
    final = sorted(kept, key=lambda r: r["id"])
    if args.per_family_cap:
        seen, capped = collections.Counter(), []
        for rec in final:
            if seen[rec["family"]] < args.per_family_cap:
                seen[rec["family"]] += 1
                capped.append(rec)
        final = capped

    with open(args.out, "w", encoding="utf-8") as fh:
        for rec in final:
            fh.write(json.dumps(rec, ensure_ascii=True) + "\n")

    final_prompts = {_norm(_by_role(r)["user"]) for r in final}
    report = {
        "toolkit": "curatorkit",
        "toolkit_version": getattr(curatorkit, "__version__", "unknown"),
        "input": args.train,
        "input_sha256": sha256_file(args.train),
        "input_rows": len(source),
        "gold_correction": {
            "targets_replaced": sum(changed.values()),
            "by_family": dict(sorted(changed.items())),
            "why": "stored targets are rule-verifier output; on these rows it is "
                   "CONFIRMED where gold is NEEDS_MORE or REFUTED",
        },
        "heldout_overlap": {
            "training_rows_dropped": len(leaked),
            "by_family": fam_count(leaked),
            "remaining_overlap_in_output": len(final_prompts & heldout_prompts),
        },
        "curatorkit_instruction_input_projection": {
            "kept": len(naive_kept),
            "of": len(clean),
            "kept_by_family": fam_count(naive_kept),
            "families_removed_entirely": sorted(
                set(fam_count(clean)) - set(fam_count(naive_kept))),
            "stage_counts": naive_res.stage_counts,
            "cause": "ExactDeduplicator hashes instruction + output and ignores input; "
                     "rows with different evidence and the same templated answer are "
                     "removed as duplicates",
        },
        "curatorkit_full_prompt_projection": {
            "kept": len(kept),
            "of": len(clean),
            "rejected": len(rejected),
            "kept_by_family": fam_count(kept),
            "stage_counts": res.stage_counts,
            "config_guard": guard.to_dict(),
            "post_run_guard": post.to_dict(),
            "wall_clock_seconds": round(elapsed, 2),
        },
        "per_family_cap": args.per_family_cap,
        "output": args.out,
        "output_rows": len(final),
        "output_by_family": fam_count(final),
        "output_gold_distribution": dict(sorted(
            collections.Counter(r["gold"] for r in final).items())),
        "output_sha256": sha256_file(args.out),
        "note": "Output rows carry the original, uncleaned text of the rows that passed "
                "curation, so training and held-out prompts are rendered identically.",
    }
    os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"wrote {args.out}: {len(final)} rows {fam_count(final)}")
    print(f"wrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
