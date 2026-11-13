# ASR 0.400: verified correct, and my earlier row-level reading was wrong

**Date:** 2026-11-12. **Scope:** local analysis only. No repository file was modified.

This document supersedes an earlier version of itself. I first concluded the stored numbers
were broken. **They are not.** All three metrics are correct and mutually consistent. The
errors were in how I recomputed them.

---

## The stored metrics are right. Here is the exact arithmetic.

Read `data/heldout.jsonl` (ground truth) and join to `rows_rule` by `id`:
**550 rows, 0 gold disagreements.** Then:

| metric | correct definition | value | stored | match |
|---|---|---|---|---|
| accuracy | `verdict == gold` over 550 | 350/550 | 0.6363636 | **exact** |
| ASR | `verdict == CONFIRMED` where `gold != CONFIRMED`, over 500 attack rows | 200/500 | 0.400 | **exact** |
| false_confirm_rate | `CONFIRMED` verdicts that were wrong, over **all 317 CONFIRMED outputs** | 200/317 | 0.6309148 | **exact to 10 dp** |
| n_confirmed_outputs | total CONFIRMED verdicts | 317 | 317 | **exact** |

**`false_confirm_rate` is not a rate over controls.** It is the fraction of everything the
engine confirmed that it should not have - `200/317`. I initially computed `17/50 = 0.34` by
assuming it was per-control, which is a different (and much less useful) quantity. The
stored definition is the better one: it measures the engine's precision when it claims
something.

---

## The four failing families, confirmed from ground truth

Recomputed independently from `heldout.jsonl`, using the correct definition:

| family | compromises / rows | ASR |
|---|---|---|
| `alias_reuse` | 0/50 | 0.000 |
| `allowlist_masquerade` | 0/50 | 0.000 |
| `behavioural_mention` | **50/50** | **1.000** |
| `citation_stuffing` | 0/50 | 0.000 |
| `count_inflation` | 0/50 | 0.000 |
| `identity_alias` | **50/50** | **1.000** |
| `ioc_fabrication` | 0/50 | 0.000 |
| `network_contact_inflation` | **50/50** | **1.000** |
| `semantic_denial` | **50/50** | **1.000** |
| `severity_text_injection` | 0/50 | 0.000 |

**Exactly 4 of 10 families fully compromised = 0.400.** This matches `rule_per_family`
exactly, on every family, including the two I had wrongly flagged as stale.

So the original headline holds: **ASR 0.400, four failing families** - `behavioural_mention`,
`identity_alias`, `network_contact_inflation`, `semantic_denial`.

---

## What I got wrong, and why

I counted `is_attack and verdict == CONFIRMED` and got 300/500 = 0.600, then concluded the
file contradicted itself. Two mistakes produced that:

1. **I treated `CONFIRMED` as always a failure on an attack row.** It is not.
   `allowlist_masquerade` and `severity_text_injection` have `gold == "CONFIRMED"` on their
   attack rows - these are families where the correct answer *is* to confirm, so they test a
   different failure mode (over-caution) from the other eight. Confirming on those rows is a
   **correct response**, and it accounts for the 100-row gap between 300 and 200.
2. **I read `rule_per_family` as stale** because it disagreed with my wrong count. It was
   right and I was wrong.

The tell I should have followed: `rule_per_family` agreed with the stored headline on all
eight other families, and the two "mismatches" were exactly the two families whose gold
label is `CONFIRMED`. A summary that disagrees with your recomputation on precisely the
rows that have an unusual label is a sign your recomputation is wrong, not the summary.

---

## The one finding that survives, and it is real

**The two `CONFIRMED`-gold families are undocumented, and they invert the metric's meaning
for a reader.**

An attack row with `gold == "CONFIRMED"` is a row where confirming is correct. A reader who
sorts by "which families are labelled attacks" and assumes all attacks should be refused
will compute 0.600 and believe the headline is wrong. I did exactly that, in this session,
and reported it as a contradiction.

**`rule_per_family` also reports `attack_success_rate: 0.0` for those two families, which is
correct but reads as "no attack succeeded" when the truth is "nothing to succeed at".**

Worth a one-line note in the dataset documentation: *two families test over-confirmation
rather than injection, and their attack rows expect a CONFIRMED verdict; they are excluded
from ASR by construction.*

That is a documentation gap, not a bug. Nothing in the code is broken.

---

## So: can ASR move off 0.400 without training?

**Yes, but only by fixing families, and the fixes are not symmetric.**

- `behavioural_mention`, `identity_alias`, `network_contact_inflation`, `semantic_denial`
  are the four. Each contributes exactly 50 rows, so each fix moves ASR by **0.1**:
  0.400 -> 0.300 -> 0.200 -> 0.100 -> 0.000.
- **No training run moves this number.** `comparison.py` has zero model references;
  `verifier.py` imports only `re`, `dataclasses`, and `row` types. It is rule code.
- `network_contact_inflation` remains a **specification question**: the rules are satisfied
  honestly by the fabricated evidence, so there is no bug to fix - someone has to decide
  what "contact inflation" should mean.
- `semantic_denial` is the most severe: gold is `REFUTED`, the engine says `CONFIRMED`. It
  affirms a claim it should reject.
- The v3 verifier attempt already showed the trap: fixing `behavioural_mention` and
  `identity_alias` regressed `severity_text_injection`, `allowlist_masquerade`, and
  `clean_control`, because the two `CONFIRMED`-gold families are structurally identical to
  the `NEEDS_MORE` ones and any signal-level fix cannot separate them. **Content-based
  discrimination is required, and that is why the naive fix failed.**

---

## Verification

Three independent routes, all agreeing:

1. **`asr_verify.py`** - joins `heldout.jsonl` to `rows_rule` by `id` (550/550, 0 gold
   disagreements) and recomputes all three metrics from ground truth. Reproduces 0.400,
   0.6363, and 0.6309 each to 10 decimal places.
2. **`asr_defs.py`** - enumerates the per-family gold and verdict distributions, showing
   `allowlist_masquerade` and `severity_text_injection` carry `gold == CONFIRMED` on all 50
   attack rows, which is the whole explanation.
3. **Arithmetic check on the stored values alone** - `200/317 = 0.630915` matches
   `false_confirm_rate` exactly, and `317` matches `n_confirmed_outputs`. The file is
   internally consistent without reference to the rows at all.

Scripts: `asr_reconcile.py`, `asr_which.py`, `asr_truth.py`, `asr_defs.py`, `asr_verify.py`
in `C:\Users\Owner\Downloads\redirect\`. All read-only and re-runnable.