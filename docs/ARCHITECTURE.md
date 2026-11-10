# Architecture

Two layers. The upstream PHANTOM DFIR verification path is imported and measured **unmodified**; everything else is the safety layer added on top.

## Where the defect lives

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ UPSTREAM PHANTOM DFIR  (imported, never modified)                       │
  │                                                                         │
  │   investigator ──produces──► hypothesis {claim, ioc, verified_sources}  │
  │        │                              ▲                                 │
  │        │              ┌───────────────┘                                 │
  │        │              │  agents/evidence.py:83-86                       │
  │        │              │  one source key PER PLUGIN PER PID              │
  │        │              │  :168-171 no alias canonicalisation             │
  │        │              │  => 1 artifact becomes 3-5 "sources"            │
  │        │              │                                                 │
  │        ▼              │                                                 │
  │   ┌───────────────────┴──────────┐                                      │
  │   │ skeptic.py                   │   advertised as adversarial          │
  │   │  :76 injects required_verdict│   cross-examination                  │
  │   │  :113 _enforce_evidence_rules│                                      │
  │   │    :121-130  n>=3 -> CONFIRMED◄──❌  VERDICT SET BY AN INTEGER      │
  │   │              n==0 -> REFUTED │       the audited agent controls n    │
  │   │  :259-265 re-queries <3 srcs │                                      │
  │   └──────────────┬───────────────┘                                      │
  │                  ▼                                                      │
  │   ┌──────────────────────────────┐                                      │
  │   │ correlation/confidence.py    │                                      │
  │   │  :18-25 BENIGN_INDICATORS    │  ❌ substring match on the CLAIM's   │
  │   │        includes "benign"     │     own wording sets severity        │
  │   │  :47-48 returns CLEARED      │                                      │
  │   │        BEFORE counting       │                                      │
  │   └──────────────────────────────┘                                      │
  └─────────────────────────────────────────────────────────────────────────┘

  MEASURED CONSEQUENCE (n=550, seed 1729)
    five LLM strategies incl. NO LLM and a refute-everything model
                                        ->  byte-identical confidences
    attack success rate 0.800 | false-confirm 0.839 | dangerous-miss 0.427
```

## What this repository adds

```
  ┌──────────────────────┐   ┌──────────────────────┐   ┌───────────────────────┐
  │ red_team/rows.py     │   │ harness/env.py       │   │ evidence_scanner/     │
  │                      │   │                      │   │ scanner.py            │
  │ 8 attack families    │   │ drives the REAL      │   │                       │
  │ + clean control      │   │ upstream modules     │   │ untrusted content     │
  │                      │   │                      │   │ treated as DATA only  │
  │ gold labels defined  │   │ tool layer stubbed   │   │                       │
  │ by DISTINCT          │   │ LLM injectable       │   │ SHA-256 per artifact  │
  │ ARTIFACTS, not by    │   │                      │   │ findings stored apart │
  │ source-key count     │   │ => runs with no GPU, │   │ fence prevents escape │
  │                      │   │    no Volatility     │   │                       │
  │                      │   │                      │   │ recall 15/15          │
  │                      │   │                      │   │ false positives 0/12  │
  └──────────┬───────────┘   └──────────┬───────────┘   └───────────────────────┘
             │                          │
             └────────────┬─────────────┘
                          ▼
            ┌─────────────────────────────────────┐
            │ evaluation/                         │
            │   metrics.py    Wilson, exact       │
            │                 McNemar, Holm       │
            │   baseline.py   BEFORE (upstream)   │
            │   comparison.py BEFORE vs AFTER     │
            └──────────────┬──────────────────────┘
                           ▼
            ┌─────────────────────────────────────┐
            │ grounding/verifier.py   THE REPAIR  │
            │                                     │
            │ 1 corroborate by ARTIFACT IDENTITY   │
            │   not by source-key string          │
            │ 2 require BEHAVIOURAL relevance      │
            │ 3 require VALIDATED CITATIONS        │
            │   that mention and do not deny       │
            │ 4 claim wording is INERT             │
            │   benign needs vendor-path evidence  │
            │ 5 abstention (NEEDS_MORE) is a       │
            │   first-class outcome                │
            └──────────────┬──────────────────────┘
                           ▼
  MEASURED (n=550, paired, McNemar p=1.2e-60, no row regressed)
    attack success 0.800 -> 0.400 | false-confirm 0.839 -> 0.631
    broken down by ATTACK AUTHORSHIP, which is the honest split:
      self-authored families (8)          ASR 0.143
      independently-authored families (3) ASR 1.000  <- all three defeated the repair
    the three independent families test the SPEC, not the code: an outside model was
    given the specification and never the implementation
    dangerous-miss 0.427 -> 0.000 | capability retention 1.000 -> 1.000
```

## The rule that the repair enforces

```
  claim: "evil.exe is a malicious C2 beacon"

  presented evidence                       BEFORE            AFTER
  ---------------------------------------  ----------------  ----------------
  1 artifact, 5 source keys               CONFIRMED ❌       NEEDS_MORE ✅
  1 artifact, 3 plugin aliases            CONFIRMED ❌       NEEDS_MORE ✅
  claim reworded to include "benign"      CLEARED   ❌       CONFIRMED ✅
  IOC named in 4 unremarkable records     CLEARED   ❌       NEEDS_MORE ✅
  IOC named in 4 behavioural records      CLEARED   ❌       CONFIRMED ⚠️ FAMILY 8
  IOC absent from all evidence            REFUTED   ✅       REFUTED   ✅
  unknown binary in unknown path          NEEDS_MORE ✅      NEEDS_MORE ✅
  unmanipulated control row               CONFIRMED ✅      CONFIRMED ✅
```

The last-but-two row is the honest failure. Four artifacts from genuine behavioural
plugins — malfind, netscan, dlllist, cmdline — each merely *name* the file while
describing ordinary activity. The repair confirms all 50 such rows. Behavioural
relevance is not evidential weight, and this is the one attack family written after
the verifier was frozen.

## Data flow for training

```
  red_team/rows.py ──► repair/dataset.py ──► data/train.jsonl    (2400 rows)
                            │               data/heldout.jsonl  ( 400 rows)
                            │
                            │  fence header carries id + artifact + plugin
                            │  check_roundtrip re-runs the verifier on every
                            │  rebuilt row and asserts verdict, artifact count
                            │  and citations all reproduce  <-- integrity gate
                            ▼
                    repair/train_qlora.py
                            │  AlignTune SFTConfig + 4-bit NF4 QLoRA
                            │  --dry-run validates everything but the weights
                            ▼
                      ⛔ BLOCKED: Cohere checkpoints gated, HTTP 401
                            │
                    repair/eval_model.py
                            │  greedy decoding, deterministic
                            │  hallucinated citations and unparseable output
                            │  counted as FAILURES, never credited
                            └--rule-only runs today without weights
```

## Why the harness needs no GPU

The defects are in the verification and scoring layer, not in evidence collection, so
the harness stubs the tool layer and drives the real `skeptic`, `confidence` and
`evidence` modules directly. Every finding in this repository is therefore reproducible
on any machine, with no memory image, no Volatility, and no disk image — which is also
the honest limit of what has been tested.