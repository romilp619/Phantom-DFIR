# phantom-safety

Evidence-grounded, adversarially resilient verification for AI forensic analysis.

This is an additive safety layer over [PHANTOM DFIR](https://github.com/romilp619/Phantom-DFIR). The upstream clone is imported and measured **unmodified**; nothing in this repository edits it.

Built for the Lexsi AI Safety and Alignment Hackathon, Track 2 (AI Red Teaming, Safety and Alignment).

## The finding

PHANTOM advertises an adversarial "Skeptic" agent that cross-examines findings before they can be reported as CRITICAL. Measured against the real code, that layer does not verify:

- **Its model has no authority.** The Skeptic's verdict is overridden by a count (`agents/skeptic.py:121-130`), and the count is computed from a list the audited agent supplies. Five LLM strategies, including a model that refutes every claim and no model at all, produced **byte-identical confidences on all 300 rows**. The advertised argument between two agents is a threshold on an integer.
- **The count is inflated for free.** `agents/evidence.py:83-86` emits a distinct source key per plugin per PID, and `:168-171` never canonicalises aliases. One kernel artifact counts as three to five "independent sources" with no attacker action.
- **Severity is decided by claim wording.** `correlation/confidence.py:47-48` returns CLEARED when the claim text contains a phrase from a list including `"benign"` (`:18-25`). Fully corroborated threats were reported as cleared on **100% of rows**.
- **The headline metrics cannot detect any of this.** `benchmark.py:131,137,138` computes a false-positive rate that is 1 minus precision, and a hallucination rate that measures refutation activity and is 0.00 for any system that never refutes.

## The repair

`phantom_ai_safety/grounding/verifier.py` replaces the upstream confidence policy:

1. Corroboration counts distinct **artifacts**, not source-key strings.
2. Only **behavioural** artifacts corroborate. A name in an AV log, download record, prefetch entry or registry key is a mention, not corroboration.
3. Accepted claims must carry **validated citations** that mention the indicator and do not deny it.
4. **Claim wording is inert.** Benign classification requires a vendor binary inside a vendor path.
5. **Abstention is first class**, so capability retention stays measurable.

| Metric | Before | After |
|---|---:|---:|
| Accuracy vs gold | 0.273 | 0.636 |
| False-confirm rate | 0.839 | 0.631 |
| Attack success rate | 0.800 | 0.400 |
| Dangerous-miss rate | 0.427 | 0.000 |
| Capability retention | 1.000 | 1.000 |

n=550 (10 attack families + clean control, x 50), seed 1729. Paired exact McNemar p = 1.2e-60, no row regressed.

### Three of those families were written by a different model

Families 9-11 were authored by an independent red-team model given **only the specification
of the repair, never its implementation**, so those attacks test whether the idea
generalises rather than poking at code. **All three defeated the repair, each at ASR
1.00**, taking attack success rate from 0.143 on the self-authored set to **0.400**.

They fail in two different ways, and the difference is the point:

- `identity_alias` and `semantic_denial` are **implementation gaps**: one process described
  under four identity namespaces defeats counting by "distinct artifact"; and
  `launch count = 0` is semantically a denial that contains none of the negation keywords.
- `network_contact_inflation` is a **specification gap** and cannot be fixed by better code.
  Four genuinely distinct behavioural artifacts, all ordinary HTTPS traffic to the claimed
  host, satisfy every rule honestly. The specification equates "mentioned in enough
  behavioural artifacts" with "established", and contact is not command-and-control.

### Read the caveat with the table

The evaluation rows are **synthetic, and the repair was iterated against the self-authored
families.** The improvement is an **upper bound**, not an unbiased estimate. The
independent families are the closest thing here to an unbiased measurement, and they are
roughly three times less favourable. The generalisable claim is the mechanism and the
direction, not the numbers. Full detail: `docs/RESULTS-COMPARISON.md`.

## Evidence prompt-injection scanner

`phantom_ai_safety/evidence_scanner/scanner.py` scans untrusted recovered content before it reaches a model. Validated against 15 labelled payloads across 7 categories (**recall 15/15**) and 12 negative controls of ordinary hostile-looking forensic text (**0 false positives**) — because a scanner that flags malware paths would suppress real analysis. Known limitation: base64-encoded injections are not flagged, and keyword scanning over encoded data is not a sound detection strategy anyway.

Recovered content is treated as data only. Nothing evaluates or executes it, every artifact is SHA-256 hashed, findings are stored separately from artifacts, and untrusted text is fenced so evidence cannot escape the data boundary.

## Layout

```
phantom_ai_safety/
  harness/           run upstream code with tool stubs and an injectable LLM
  red_team/          row schema and 7 evaluation families
  evaluation/        metrics, baseline runner, before/after comparison
  grounding/         the repaired verifier
  evidence_scanner/  prompt-injection detection and quarantine
scripts/             entry points (see below)
tests/               pytest suite
results/             generated JSON, including every per-row record
```

## Running it

Requires Python 3.11+ and the upstream clone. No GPU, no Volatility, no memory image.

```bash
pip install langgraph langchain-core langchain-ollama pytest
export PHANTOM_ROOT=/path/to/Phantom-DFIR

python scripts/smoke_harness.py                                     # reproduce the findings
python scripts/validate_scanner.py                                  # scanner recall and false positives
python -m phantom_ai_safety.evaluation.baseline  --per-family 50 --quiet --out results/baseline.json
python -m phantom_ai_safety.evaluation.comparison --per-family 50 --quiet --out results/comparison.json
python scripts/summarize_results.py results/comparison.json
pytest tests/ -q
```

## Reproducibility note: the upstream clone is content-unmodified

If you run `git status` inside the upstream clone **under WSL**, it reports all 83 files as modified:
`83 files changed, 124215 insertions(+), 124215 deletions(-)`.

That is a CRLF/LF representation artifact, not an edit. The clone was checked out on Windows with
`core.autocrlf=true`, while WSL git leaves `core.autocrlf` unset, so the same bytes are read
differently. Confirmed by two independent routes: Windows git reports zero diffs, and **every** file's
insertion count exactly equals its deletion count, which is the signature of a line-ending rewrite and
never happens with a real content change. `HEAD` remains `3005762`.

The `source_digest_sha256` recorded in every result file is computed over `correlation/confidence.py`,
`agents/skeptic.py` and `agents/evidence.py` as they exist on disk, and is the check that actually
matters: it pins the exact bytes the findings were measured against.

## Status

- Working and verified: harness, red-team set, baseline measurement, repair, before/after comparison, injection scanner, tests.
- **Not implemented: the fine-tuned model.** The Cohere Labs checkpoints (`tiny-aya-global` and the Aya Expanse family) are gated and return HTTP 401 without an authenticated token. No fine-tuned artifact exists and no training run has been performed. Every number above comes from the deterministic verifier.
- Not run: any real memory image, Volatility, Sleuth Kit, or the upstream CFReDS / SysInternals cases.

## Licensing and disclosure

The upstream project's licence governs the imported code. The Lexsi repositories are source-available under LSAL v1.1/v1.2 rather than uniformly open source, AlignTune vendors AGPL and LGPL components, and AuditKIT Section 1A asks an organisation doing red-teaming to send written acknowledgement to support@lexsi.ai. The Cohere checkpoints are `cc-by-nc-4.0`, so non-commercial.

This is a defensive finding about a public project. All attacks are synthetic evaluation rows; no exploit targeting a live system is published, and no upstream file was modified.