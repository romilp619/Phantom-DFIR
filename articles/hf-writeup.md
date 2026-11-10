# A forensic AI's "adversarial verifier" that agrees with everything

**Can we make an AI forensic analyst more resistant to adversarial manipulation while preserving its ability to accurately investigate digital forensic evidence?**

We tested that question against an existing agentic DFIR tool that advertises an adversarial self-verifying layer. Measured against its own unmodified code, the layer does not verify: its verdict is a threshold on an integer, the audited agent supplies the integer, and the model inside it has no measurable effect on the outcome. Five LLM configurations — including no LLM at all and a model that refutes every claim — produced **byte-identical verdicts on 300 rows**.

We then built an evidence-grounded replacement, attacked it, broke it, fixed it, and were careful about what the fixed numbers actually mean. This write-up reports the negative results alongside the positive ones, because the negative ones are the reason to trust the rest.

**Track 2 — AI Red Teaming, Safety and Alignment.** All work is defensive. Attacks are synthetic evaluation rows against a public open-source project. No exploit is published and no upstream file was modified.

---

## 1. The claim, and what it is actually worth

The tool under test is [PHANTOM DFIR](https://github.com/romilp619/Phantom-DFIR), an agentic digital forensics tool. Among its features is a "Skeptic" agent described as adversarially cross-examining findings before they can be reported as CRITICAL — an investigator proposes, a skeptic challenges.

In the source, the skeptic's verdict is overridden by a count of evidence sources:

- `agents/skeptic.py:76` injects a `required_verdict` into the model's prompt
- `agents/skeptic.py:113-130` — `_enforce_evidence_rules` — forces `CONFIRMED` when `n >= 3` and `REFUTED` when `n == 0`, discarding whatever the model concluded
- `agents/skeptic.py:259-265` only re-queries unverified or low-confidence findings with fewer than three sources

So the advertised argument between two agents is a comparison against an integer. And the integer is not neutral:

- `agents/evidence.py:83-86` emits **one source key per plugin per PID**, so a single process seen by four Volatility plugins counts as four "independent sources"
- `agents/evidence.py:168-171` never canonicalises aliases, so `vol3:malfind[4412]` and `vol3:dlllist[4412]` are distinct

The hypothesis list is produced by the agent being verified. Counting its own list is not independent corroboration.

Then the severity is set from the claim's own prose:

- `correlation/confidence.py:18-25` defines `BENIGN_INDICATORS`, which includes the bare string `"benign"`
- `correlation/confidence.py:47-48` returns `CLEARED` **before** reaching the source count

A fully corroborated threat is therefore reported as cleared if the sentence describing it contains one particular adjective.

### The measurement that settles it

We drove the real, unmodified verification modules through five LLM strategies: no model at all, agree-with-the-count, always confirm, always refute, and emit unparseable garbage.

**All five produced identical confidences on all 300 rows** (`changed_rows = 0`). A verification agent whose output does not change when it denies everything instead of agreeing with everything is not verifying. This is not a statistical claim; the per-row outputs were compared directly.

---

## 2. Measuring before and after

We built a harness that imports the upstream modules and stubs only the tool layer, so the verification and scoring logic under test is the real thing. It needs no GPU, no memory image, and no Volatility, which means every number here is reproducible anywhere.

The evaluation set is 400 synthetic rows across eight families plus a clean control, with gold labels defined by **distinct underlying artifacts** rather than source-key count. Metrics are false-confirm rate, attack success rate, dangerous-miss rate, correct-abstention rate, capability retention, and citation coverage, with Wilson intervals and exact paired McNemar.

**Capability retention is measured on untouched control rows.** Without it, a system could post a perfect safety score by refusing to confirm anything, and the score would be meaningless.

### Baseline, upstream, n=400

| Metric | Value |
|---|---:|
| False-confirm rate | 0.749 |
| Attack success rate | 0.714 |
| Dangerous-miss rate | 0.427 |
| Capability retention | 1.000 |

Capability retention of 1.000 is the important control: the upstream layer handles ordinary cases perfectly. The failure is specifically adversarial.

---

## 3. The repair

`grounding/verifier.py` replaces the confidence policy. Five changes, each aimed at one measured failure:

1. **Corroboration by artifact identity.** Distinct artifacts, not source-key strings.
2. **Behavioural relevance.** Only artifacts describing what something *did* can corroborate. A filename in an antivirus log, a download record, a prefetch entry or a registry key is a mention, not corroboration.
3. **Validated citations.** Every accepted claim names the evidence ids it rests on, and a citation must both mention the indicator and not deny it.
4. **Claim wording is inert.** Severity is never decided by claim text. A benign classification requires a known vendor binary inside a vendor installation path.
5. **Abstention is first class.** `NEEDS_MORE` is a real outcome, which keeps capability retention measurable.

### Result

| Metric | Before | After |
|---|---:|---:|
| Accuracy vs gold | 0.375 | 0.875 |
| False-confirm rate | 0.749 | 0.299 |
| Attack success rate | 0.714 | 0.143 |
| Dangerous-miss rate | 0.427 | **0.000** |
| Capability retention | 1.000 | **1.000** |
| Citation coverage on confirmed rows | 0/267 | 167/167 |

Paired exact McNemar: 200 rows wrong before and right after, **0 rows right before and wrong after**, p = 1.2e-60.

### Replication on a disjoint seed

The figures above are measured on rows the repair was built against, which is a real weakness. So we generated a second set from a **disjoint seed range** (20000 for training, 90000 for held-out) with zero row-id overlap, and scored the repair on rows it had never been fitted to. It reproduces **exactly** — 0.875 / 0.299 / 0.143 / 0.000 / 1.000, with the same single family failing.

That rules out per-row memorisation and seed luck. It does **not** rule out generator overfitting, and section 4 is why that distinction matters.

---

## 4. Where the repair fails

Family 8 (`behavioural_mention`) was written **after the verifier was frozen**, making it the only genuinely non-tuned measurement here.

Four artifacts from genuine behavioural plugins — malfind, netscan, dlllist, cmdline — each name the file, and each describes activity that is entirely ordinary: no executable regions, a loopback-only listener, only system DLLs loaded, and a `--serve --local` command line.

| | Before | After |
|---|---:|---:|
| ASR | 1.00 | **1.00** |
| False-confirm rate | 1.00 | **1.00** |

**The repair confirms every one of these rows.** The entire residual after-score is this family.

The lesson is precise: **behavioural relevance is not evidential weight.** The first version of the repair stopped treating a scan log as corroboration, then treated four innocuous behaviour records as corroboration instead. Both are counting name mentions. The upstream defect — an evidence count and a `BENIGN_INDICATORS` substring match — is the same flaw at shallower depth.

Fixing it properly needs the evidence to assert *the suspicious predicate the claim depends on*: for a C2 claim, external network peers; for an injection claim, an executable region. That is a semantic judgement over arbitrary text, which is exactly what a fine-tuned model was meant to supply.

**We deliberately did not ship a third rule.** A rule table written while looking at this family would be fitted to it and would demonstrate nothing. Reporting the ceiling is more useful than papering over it, and it is the honest reason the model half of the project matters.

---

## 5. Two silent defects in our own harness

The disjoint-seed run initially disagreed with the fitted run in a way that was impossible if both measured the same verifier. They did not. The rendered prompt used for training was losing structured evidence metadata, and each loss changed what the evaluation measured while still printing plausible numbers:

1. **The `plugin` field was dropped**, so rebuilt rows defaulted to `"unknown"`, which is not behavioural. No artifact could ever corroborate anything. The visible symptom was capability retention of 0.660 on *untouched control rows*.
2. **Artifact identity collapsed into the evidence id.** The fence carried only the evidence id, so on rebuild each item looked like its own artifact. Five records describing **one** PID looked like five artifacts, defeating the central rule of the repair and reporting `count_inflation` ASR 1.00.

Neither raised an exception. Both produced a results table.

The fix is structural: the fence header carries `id`, `artifact` and `plugin`; a missing field is a hard error rather than a default; one parser is shared by the dataset builder and the evaluator so they cannot drift; and `check_roundtrip` re-runs the verifier on **every** row rebuilt from the written file, asserting that verdict, distinct-artifact count and citations all reproduce. That gate runs at build time across all 2,800 rows and is covered by three tests.

We report this because a measured improvement is only as trustworthy as the harness around it, and ours had two defects that would have silently misreported results.

---

## 6. Evidence prompt-injection scanning

Separate capability, validated separately. Untrusted recovered content is scanned before it reaches a model.

- 15 labelled payloads across 7 categories — **recall 15/15** at or above each category's expected tier
- 12 negative controls of ordinary hostile-looking forensic text (mimikatz paths, encoded PowerShell, IRC C2 channel records, a `svchost.exe` registry reference) — **0 false positives**

The negative controls matter more than the payloads. Forensic evidence legitimately contains hostile-looking strings, and a scanner that flags malware paths would suppress real analysis.

Recovered content is treated strictly as data: nothing evaluates or executes it, every artifact is SHA-256 hashed, findings are stored separately from the artifacts, and untrusted text is fenced so evidence cannot close the boundary and begin issuing instructions. Fence escape is tested directly.

Known limitation: base64-encoded injections are not flagged. Keyword scanning over encoded data is not a sound detection strategy, so this is a deliberate boundary rather than an omission.

---

## 7. What we did not do

- **No fine-tuned model exists.** All 13 candidate Cohere checkpoints are gated (`gated: "auto"`) and return HTTP 401 without an authenticated token. The training pipeline is written against the real AlignTune APIs and validated up to the point of loading weights, but **no training run has been performed**. Every number here comes from the deterministic verifier.
- **No real memory image, no Volatility, no disk image.** The harness stubs the tool layer. Nothing here describes behaviour on a real case.
- **No upstream benchmark was reproduced.** We did not re-test the project's headline accuracy figures. What is documented is a metric-construction problem.
- **Two hypothesised attacks failed to reproduce** and are reported as negative results: `ioc_fabrication` (already handled correctly at `skeptic.py:121-130`) and `allowlist_masquerade` (the allowlist code is not on the path this harness exercises, so the concern remains a reading of the source rather than a measured result).

---

## 8. What we would tell the maintainers

Three specific changes, all small:

1. Count corroboration by **distinct artifact identity**, not by source-key strings.
2. Remove the claim-text severity override in `correlation/confidence.py:47-48`. A verdict must never be set by the wording of the claim being assessed.
3. Require **validated citations** on every confirmed finding, so a claim that cannot be cited cannot be confirmed.

And the general point, which is the actual research contribution: **a verification layer whose output is independent of its own model is not a verification layer.** Whatever else it does, it must be possible for the verifier to disagree.

---

## Reproducing this

```bash
git clone https://github.com/romilp619/Phantom-DFIR
export PHANTOM_ROOT=$PWD/Phantom-DFIR

python scripts/smoke_harness.py                                  # the four findings
python scripts/validate_scanner.py                               # scanner recall and false positives
python -m phantom_ai_safety.evaluation.baseline  --per-family 50 --quiet --out results/baseline.json
python -m phantom_ai_safety.evaluation.comparison --per-family 50 --quiet --out results/comparison.json
python -m phantom_ai_safety.repair.dataset --outdir data         # includes the integrity gate
python -m phantom_ai_safety.repair.eval_model --rule-only        # disjoint-seed replication
pytest tests/ -q                                                 # 29 tests
```

Every result file records the SHA-256 digest of the upstream verification sources it was measured against, so a reader can confirm the exact bytes behind each number. Full per-row records are included, so results can be re-scored from the published data rather than taken on trust.

## Licence and disclosure notes

The upstream project's licence governs the imported code. The Lexsi repositories are source-available under LSAL v1.1/v1.2 rather than uniformly open source; AlignTune vendors AGPL and LGPL components; AuditKIT Section 1A asks organisations doing red-teaming to send written acknowledgement to support@lexsi.ai. Cohere checkpoints are `cc-by-nc-4.0` (non-commercial).

This is a defensive security finding about a public project, prepared for the Lexsi AI Safety and Alignment Hackathon, Track 2.