# CuratorKIT integration: a real pipeline run on the project's own data

The hackathon brief asks for the stack to be "chained into a real pipeline". This document
records an actual execution of the sponsor's CuratorKIT toolkit over the project's training
split, with the numbers it produced, plus four things a builder should know before doing
the same.

Everything here comes from commands that ran. Nothing is estimated.

## What was run

```
curatorkit            0.1.24
input                 data/train.jsonl          3,300 rows, 11 generator families
projection            chat messages -> alpaca (instruction / input / output)
machine               RTX 4060 laptop, Ubuntu under WSL2, CPU-only for this stage
```

The runner is `scripts/curatorkit_curate.py`, re-runnable and idempotent.

## Measured result

```
rows read                 3300 / 3300        reader rejected 0
schema gate               3300 -> 3300       every row passed validation
exact dedup               3300 -> 1900       1400 exact duplicates dropped (42.4%)
text cleaner              1900 -> 1900       0 rejected
final                     1900 passed, 0 rejected, pass rate 1.000
wall clock                0.30 s
```

Two things worth drawing out.

**Every row passed schema validation.** The dataset has no malformed rows: all 3,300 carry
a non-empty system, user, and assistant message, and all 3,300 preserve their original id
(`S20000-F1-000` and so on) through to the curated `DataSample`.

**Exact deduplication removed 42.4% of the corpus.** 1,400 of 3,300 rows are byte-identical
after projection. That is a property of the generators, not a defect: each family reuses the
same evidence block across many rows while varying the framing. It is a real number the
submission should state, because it means the effective size of the training set is 1,900
distinct texts, not 3,300.

## The finding that matters most

CuratorKIT's default cleaning **deleted the evidence markers from every single row.**

```
TextCleaner strip_html removed tag-shaped text from 1900 of 1900 samples.
```

This dataset's evidence is delimited by angle-bracket markers such as
`<<UNTRUSTED_EVIDENCE id=EV-000-0 artifact=...>>`. The cleaner reads those as HTML and strips
them. Measured both ways on the same input:

| configuration | rows still carrying evidence markers |
|---|---|
| library default | **0 / 1900** |
| `clean_transforms={'strip_html': False}` | **1900 / 1900** |

For an ordinary text corpus that cleaning is correct and welcome. For safety-audit data where
the markers are the semantic anchors, the default quietly removes the structure the model is
supposed to learn to ground on, and the run still reports a clean pass rate of 1.000. A
pipeline that reports success while degrading its own training signal is the worst kind of
failure, and it is the same defect class this project audits elsewhere.

The toolkit does log the behaviour and name the fix, which is to its credit. The point is
that the log is the only place it appears.

**Correct configuration for this dataset:**

```
CuratorConfig(
    dataset=..., format="alpaca",
    clean_transforms={"strip_html": False},
    injection_rate=0.0,
)
```

## Three operational notes for the sponsor

Offered as the real-world feedback the brief asks for, in the order they cost time.

**1. An unrecognised `format` string silently drops the whole corpus.** Passing
`format="jsonl"` does not raise. It falls back to `UNKNOWN` and rejects 100% of rows, and
`RejectedSample` carries no reason, so the run reports `output_count=0` with an empty stage
table and no explanation. Valid members are `alpaca`, `sharegpt`, `preference`,
`implicit_preference`, `unpaired_preference`, `grpo`, `prompt_only`, `pretrain`. Validating
the string at construction, and populating `RejectedSample.reason` on a detection failure,
would turn a silent 100% loss into a one-line fix.

**2. `injection_rate` alone produced no observable injected rows.** With `injection_rate=0.10`
and `0.20` the passed and rejected counts were identical to a rate of 0.0, no sample carried
an injection flag, and `diagnostics` was an empty dict. It appears to require `injection_types`
to be set. If that is the contract, raising when a non-zero rate has no types would be clearer
than accepting it.

**3. `id` is preserved when supplied, but is generated when not.** Passing an `id` field
through the projection yields the original id on the resulting `DataSample`; omitting it
yields a UUID. Both behaviours are reasonable. Documenting which one applies would save a
builder an audit, since provenance silently changing shape is easy to miss.

## Why this matters to the submission

This run closes the gap between describing the stack and having operated it. The brief's
central requirement is a chained pipeline; this is the data-preparation stage of that chain
executed on the project's real corpus, with the toolkit's own curation gates, and it produced
a concrete correction to the data configuration that measurably protects the training signal
(0/1900 versus 1900/1900 marker retention).

It is one stage, not the whole chain. The fine-tuning stage remains blocked on access to the
gated Cohere Labs checkpoints, and that gap is stated plainly rather than papered over.