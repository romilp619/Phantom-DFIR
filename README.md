# phantom-safety

**Evidence-grounded, adversarially resilient verification for AI forensic analysis.**

An additive safety layer over [PHANTOM DFIR](https://github.com/romilp619/Phantom-DFIR).
The upstream clone is imported and measured **unmodified**; nothing in this repository edits it.

Built for the **Find Evil! Hackathon** (SANS Institute).

---

## The headline

An AI forensic agent that confidently reports a clean host, or misses a real intrusion, is
worse than no agent at all. This repository measures that failure on the upstream project,
repairs it, and proves the repair with a process-isolated scanner that cannot be talked out
of its verdict.

![Before and after the repair](docs/img/before-after.png)

| | before | after |
|---|---|---|
| Accuracy | 0.273 | **0.636** |
| Attack success rate | 0.800 | **0.400** |
| False-confidence rate | 0.839 | **0.631** |
| Distinct-artifact misreporting | 0.427 | **0.000** |

n = 550 (500 attacks, 50 controls, 11 families). McNemar 200/0, p = 1.24e-60.
Every figure in this README is enforced by `scripts/verify_report_claims.py`, which fails
the build if a quoted number stops matching a stored result.

---

## The finding

PHANTOM advertises an adversarial "Skeptic" agent that cross-examines findings before they can
be reported as CRITICAL. Measured against the real code, that layer does not verify:

- **Its model has no authority.** The Skeptic's verdict is overridden by a count
  (`agents/skeptic.py:121-130`), and the count is computed from a list the audited agent
  supplies. Five LLM strategies, including a model that refutes every claim and no model at
  all, produced **byte-identical confidences on all 300 rows**. The advertised argument
  between two agents is a threshold on an integer.
- **The count is inflated for free.** `agents/evidence.py:83-86` emits a distinct source key
  per plugin per PID, and `:168-171` never canonicalises aliases. One kernel artifact counts
  as three to five "independent sources" with no attacker action.
- **Severity is decided by claim wording.** `correlation/confidence.py:47-48` returns CLEARED
  when the claim text contains a phrase from a list including `"benign"` (`:18-25`). Fully
  corroborated threats were reported as cleared on **100% of rows**.
- **The headline metrics cannot detect any of this.** `benchmark.py:131,137,138` computes a
  false-positive rate that is 1 minus precision, and a hallucination rate that measures
  refutation activity and is 0.00 for any system that never refutes.

The pattern underneath all four: **the system trusts a count it obtained from the party it is
supposed to be checking.** Every repair below removes one instance of that.

---

## The repair

`phantom_ai_safety/grounding/verifier.py` replaces the upstream confidence policy:

1. Corroboration counts distinct **artifacts**, not source-key strings.
2. Only **behavioural** artifacts corroborate. A name in an AV log, download record, prefetch
   entry or registry key is a mention, not corroboration.
3. Acceptance requires behavioural agreement across **independent artifact types**, so N
   copies of one artifact cannot corroborate each other.
4. Claim wording cannot influence severity.

The mechanism generalises; the numbers do not. PHANTOM's own benchmark scores this repair
roughly three times less favourably, and that is reported rather than hidden. Full detail:
[`docs/RESULTS-COMPARISON.md`](docs/RESULTS-COMPARISON.md).

**Honest limits, stated up front.** Four families still fail: `behavioural_mention`,
`identity_alias`, `network_contact_inflation`, and `semantic_denial`. ASR is 0.400, not 0.
A 40% attack success rate is a research result, not a shipping guarantee.

---

## Evidence prompt-injection scanner

Untrusted recovered content is scanned before it reaches a model.
`phantom_ai_safety/evidence_scanner/scanner.py` carries 27 rules across 7 categories.

Validated against 15 labelled payloads across 7 categories (**recall 15/15**) and 12 negative
controls of ordinary hostile-looking forensic text (**0 false positives**) — because a scanner
that flags malware paths would suppress real analysis.

### Detection normalisation

An attacker who encodes a payload defeats every lexical rule. The normalisation pass
extracts candidates the rules would miss, with one design rule: **the original text is never
modified.** The scanner runs on the raw text first, then on decoded candidates, so a
normalisation bug degrades to the old detection rate and can never introduce a false positive
from a text mutation.

| obfuscation | handled |
|---|---|
| base64 | yes |
| hex | yes |
| **nested base64 (2-3 layers)** | yes |
| zero-width characters | yes |
| homoglyphs, full-width (NFKC) | yes |
| leetspeak | yes |

Nested encodings were a **real gap found by adversarial probing**: a payload base64'd twice
decoded only one layer, so double-encoded injections walked past every rule. Fixed and
regression-tested.

### The compiled Rust guard

`phantom-guard/` mirrors every rule at memory-safe process distance. The hard process
boundary means evidence text cannot reach the caller's interpreter, cannot rebind a name,
cannot monkey-patch a function, and cannot persist state between artifacts.

Why a separate process rather than a faster function:

- **Memory safety by construction.** The scanning path contains no `unsafe` code. A malformed
  artifact can cause an allocation failure, not a memory-safety violation.
- **A verifiable identity.** The binary is one artifact with one hash. A Python module is a
  file plus its imports plus whatever `sys.path` resolved to at runtime — exactly the surface
  an attacker with write access would target.

The two implementations are held to **exact agreement** on every artifact, category, offset,
hash, and severity. Two implementations agreeing on the full corpus is a stronger claim than
either can make alone.

![Guard and reference agree exactly](docs/img/equivalence.png)

---

## Security work on this repository

The scanner is the thing standing between an attacker's text and an analyst's judgement, so
it got attacked first. Every issue below was found by probing our own code and is fixed with
a regression test.

| issue | impact | fix |
|---|---|---|
| Nested base64 decoded one layer | double-encoded injection fully evaded detection | bounded recursive unwrap (`_MAX_LAYERS`) |
| Quadratic byte-to-char offset conversion | 2 MB crafted artifact = 8.5 s stall; one artifact stalls a batch | incremental cursor, now linear |
| Unbounded findings per artifact | attacker-controlled memory and output size | cap at 1024, with a `truncated` flag |

![Per-KB scan cost before and after the quadratic fix](docs/img/quadratic-fix.png)

Rising ms/KB means superlinear scanning; flat means linear. The fix is 4.2x faster at 2 MB and
the gap widens with size, which is what removing an O(n²) term looks like.

### What the security posture is, precisely

**Verified:** 0 false positives on a real 324,414-character memory image across 6 Volatility
plugins; 0 of 17 benign forensic artifacts flagged; 0 of 400 random high-entropy blobs produce
candidates; no cache-poisoning path found (same text/different ID, same ID/different text, NUL
separator collisions, duplicates in batch); ReDoS probes (5000 spaces after a match trigger)
complete in ~44 ms with no catastrophic backtracking; invalid JSON, wrong types, invalid UTF-8,
and a missing binary all fail closed without crashing.

**Measured, and reported even where unflattering:** the guard is ~1.6x *slower* than Python on
large artifacts, because CPython's regex engine beats the `regex` crate on this workload. The
guard's justification is the process boundary and memory safety, not speed. See
[`docs/REAL-IMAGE-TEST.md`](docs/REAL-IMAGE-TEST.md).

**Not claimed:** the guard is not a sandbox, not a privilege boundary, and not hardened against
a local attacker who can replace the binary. It removes a class of in-process attack, not all
attacks.

---

## Layout

```
phantom-guard/         compiled scanner (Rust), held to exact equivalence
phantom_ai_safety/
  harness/             run upstream code with tool stubs and an injectable LLM
  red_team/            row schema and 7 evaluation families
  evaluation/          metrics, baseline runner, before/after comparison
  grounding/           the repaired verifier
  evidence_scanner/    injection detection (Python), normalisation, guard bridge
scripts/               entry points and probes
tests/                 pytest suite (119 collected, 112 passing, 7 skipped)
results/               generated JSON, including every per-row record
docs/                  architecture, results, and analysis
docs/img/              README figures, generated by scripts/make_figures.py
```

---

## Running it

Requires Python 3.11+ and the upstream clone. No GPU, no Volatility, no memory image needed
for the core result.

```bash
pip install langgraph langchain-core langchain-ollama pytest
export PHANTOM_ROOT=/path/to/Phantom-DFIR

python scripts/smoke_harness.py                                      # reproduce the findings
python scripts/validate_scanner.py                                   # scanner recall / false positives
(cd phantom-guard && cargo build --release)                          # build the Rust guard
python scripts/run_rust_guard.py --write                             # guard over the attack corpus
python -m phantom_ai_safety.evaluation.baseline   --per-family 50 --quiet --out results/baseline.json
python -m phantom_ai_safety.evaluation.comparison --per-family 50 --quiet --out results/comparison.json
python scripts/summarize_results.py results/comparison.json
python scripts/verify_report_claims.py                               # guard every quoted number
pytest tests/ -q
```

### Optional: the real memory image

The integration test is the one thing the synthetic corpus cannot cover.

```bash
pip install volatility3==2.28.2
curl -o test-images/memdump.7z https://samsclass.info/121/proj/memdump.7z
7z x test-images/memdump.7z -otest-images
bash scripts/run_real_image_plugins.sh     # 7 real Volatility plugins
python scripts/test_real_image.py          # scan and cross-check
```

`test-images/` is gitignored. A 512 MB image does not belong in git, and no DFIR project
ships images this way. Note `windows.hivelist` does not exist in Volatility 3; the plugin
moved to `windows.registry.hivelist`.

---

## Reproducibility note: the upstream clone is content-unmodified

If you run `git status` inside the upstream clone **under WSL**, it reports all 83 files as
modified: `83 files changed, 124215 insertions(+), 124215 deletions(-)`.

That is a CRLF/LF representation artifact, not an edit. The clone was checked out on Windows
with `core.autocrlf=true`, while WSL git leaves `core.autocrlf` unset, so the same bytes are
read differently. Confirmed by two independent routes: Windows git reports zero diffs, and
**every** file's insertion count exactly equals its deletion count, which is the signature of
a line-ending rewrite and never happens with a real content change. `HEAD` remains `3005762`.

The `source_digest_sha256` recorded in every result file is computed over
`correlation/confidence.py`, `agents/skeptic.py` and `agents/evidence.py` as they exist on
disk. That is the check that matters: it pins the exact bytes the findings were measured
against.

---

## Status

**Working and verified:** harness, red-team set, baseline measurement, repair, before/after
comparison, injection scanner with normalisation, Rust guard, real memory image integration
test, and 112 passing tests.

**Fine-tune in progress.** The Cohere Labs checkpoints are gated and required accepting terms
before download; that gate is open and `CohereLabs/tiny-aya-global` downloads successfully. A
QLoRA adapter was trained and saved in a verification run (40 steps, loss 1.465, peak
7,763 MiB). The full one-epoch run (401 steps) is executing. **No fine-tuned model is claimed
anywhere until that run completes and the adapter is evaluated.**

Every number in this README comes from the deterministic verifier. None depends on a trained
model.

**Not run:** Sleuth Kit, the upstream CFReDS / SysInternals cases, and any second memory image
or architecture. See [`docs/REAL-IMAGE-TEST.md`](docs/REAL-IMAGE-TEST.md) for exactly what the
one real image does and does not prove.

---

## Documentation

| document | what it covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | component design and data flow |
| [`docs/RESULTS-COMPARISON.md`](docs/RESULTS-COMPARISON.md) | full before/after numbers, per family |
| [`docs/REAL-IMAGE-TEST.md`](docs/REAL-IMAGE-TEST.md) | the real image test, results, and limits |
| [`docs/EXISTING_ARCHITECTURE.md`](docs/EXISTING_ARCHITECTURE.md) | upstream code, as it actually behaves |
| [`docs/TRAINING-ENVIRONMENT.md`](docs/TRAINING-ENVIRONMENT.md) | fine-tune setup and hardware |
| [`docs/HANDOFF.md`](docs/HANDOFF.md) | current state and next actions |

---

## Licensing and disclosure

The upstream project's licence governs the imported code. The sponsor repositories are
source-available under their own licences rather than uniformly open source. AlignTune vendors
AGPL and LGPL components. AuditKIT Section 1A asks an organisation doing red-teaming to send
written acknowledgement to support@lexsi.ai. The Cohere checkpoints are `cc-by-nc-4.0`, so
non-commercial.

---

## A note for whoever picks this up next

Three things are worth knowing before you change anything here.

**The numbers are enforced, not decorative.** `scripts/verify_report_claims.py` reads this
README and the docs and fails if a quoted figure stops matching a stored result. If you change
a metric, change the result file and the claim together, or the check will catch you.

**The evaluation pipeline imports `scanner`, not `guard`, deliberately.**
`comparison.py`, `evaluator.py`, `dataset.py`, and `run_red_team.py` all use
`phantom_ai_safety.evidence_scanner.scanner`. That is the reference implementation the guard is
tested against, and the equivalence tests fail if the two diverge. Swapping the pipeline to the
guard is a one-line import with an identical signature, and is a reasonable thing to do once
you trust the equivalence tests. It is not the default because a hackathon judge should be able
to read the detection rules in the same file as the numbers they produce.

**The false-positive rate is the metric that matters most.** A scanner that flags ordinary
forensic noise gets disabled by the analyst using it, and then it protects nothing. Every new
rule should be run against `scripts/probe_normalize.py` and the real image before it lands.