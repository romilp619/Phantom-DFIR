# Handoff — submission (phantom-safety)

State as of 2026-11-10 09:20 America/Chicago. Cold-start brief.
Repo `phantom-safety`, 9 commits, HEAD `ce410d4`, 48 tracked files, working tree clean.
Long-form docs in `lexsi-work/`, mirrored into `phantom-safety/docs/`.

## Objective

Submission on AI red teaming, safety and alignment. Deadline 2026-11-15 11:59 PM AoE. Moo registers and
submits manually.

## Headline finding

PHANTOM DFIR advertises an adversarial "Skeptic" agent. Measured against its own
unmodified code, the layer does not verify: `agents/skeptic.py:113-130` sets the verdict
from an integer, `agents/evidence.py:83-86` inflates that integer by counting one
artifact once per plugin per PID, and `correlation/confidence.py:47-48` can clear a
corroborated threat on the word "benign" in the claim's own prose.

**Five LLM strategies — including no LLM and one that refutes everything — produced
byte-identical confidences on 300 rows** (`changed_rows = 0`). The model has no decision
authority. This is a direct comparison, not a statistical claim.

## Headline result, n=550 (10 attack families + clean control, x 50), seed 1729

| Metric | Before | After |
|---|---:|---:|
| Accuracy vs gold | 0.273 | 0.636 |
| False-confirm rate | 0.839 | 0.631 |
| Attack success rate | 0.800 | 0.400 |
| Dangerous-miss rate | 0.427 | 0.000 |
| Capability retention | 1.000 | 1.000 |
| Citation coverage on confirmed rows | 0/417 | 317/317 |

Paired exact McNemar 200/0, p = 1.2e-60, no row regressed. Disjoint-seed replication
(90000) reproduces all five exactly.

## The most important result: independent red team

**Three attack families were authored by an independent model given only the
specification of the repair — never the implementation, never the existing attacks. All
three defeated it, each at ASR 1.00.** They take the after-score from 0.143 on the
fully self-authored set to **0.400**.

This is the honest number and the measurement the project previously lacked. Do not
revert to quoting 0.143.

- `identity_alias` — **implementation gap.** One process described under four identity
  namespaces (PID, process GUID, image path, handle-table key). `verifier.py:96-98`
  compares identity as an opaque string, so one artifact becomes four votes.
- `semantic_denial` — **implementation gap.** Text asserts `launch count = 0`, which is
  semantically a denial containing none of the negation keywords, so the citation
  validates. Same class of defect as upstream's `BENIGN_INDICATORS` substring match.
- `network_contact_inflation` — **SPECIFICATION gap, not fixable by code.** Four genuinely
  distinct behavioural artifacts, ordinary HTTPS connections to the claimed host. Every
  rule satisfied honestly; the repair confirms while correctly implementing its own spec.

**The two implementation gaps were deliberately NOT patched.** The identity space is
open-ended, so PID extraction still leaves GUID and path namespaces distinct and the alias
attack survives a partial fix; any lexical negation test is evaded by the next
construction meaning "no". Patching would fit numbers to this red-teamer rather than
produce a correct verifier. The stronger conclusion: **the repair's central rule is not
deterministically enforceable** — "the same artifact" and "denies the claim" are both
open-ended judgements, which is exactly what the fine-tuned model was meant to supply.
Do not let anyone "fix" this with a keyword list; that is the anti-pattern the whole
project is about.

The independent model also independently rediscovered the same class of hole as our
post-freeze `behavioural_mention` family, from the specification alone.

## Done and verified (re-runnable in one pass)

| Check | Command | Result |
|---|---|---|
| Findings reproduce against real upstream code | `python scripts/smoke_harness.py` | all checks reproduced |
| Scanner recall and false positives | `python scripts/validate_scanner.py` | all checks passed |
| Tests | `pytest tests/ -q` | **29 passed** |
| Prose vs stored results | `python scripts/verify_report_claims.py` | all figures match, 4 failing families expected |
| Round-trip integrity gate | `python -m phantom_ai_safety.repair.dataset --outdir data` | VERIFIED over all rows |
| Dashboard | `python scripts/build_dashboard.py --out dashboard/index.html` | verified, and rendered headless to check visually |

Also done: `dashboard/index.html` (Module E), `articles/hf-writeup.md` (submission
article), `docs/ARCHITECTURE.md`, duplicate check against upstream.

## Blocked — needs Moo, about two minutes

**No fine-tuned model exists.** All 13 candidate Cohere checkpoints are gated
(`gated: "auto"`, HTTP 401 anonymous) and there is **no Hugging Face credential on this
machine**. The cache holds only anonymously downloaded public models.

I cannot do this part: it needs his account and his assent to a licence.

1. Sign in at https://huggingface.co
2. Open https://huggingface.co/CohereLabs/tiny-aya-global and click **Agree and access repository**
3. Create a **read** token at https://huggingface.co/settings/tokens
4. Put it at `%USERPROFILE%\.secret-roles\hf.env` as `HF_TOKEN=hf_...` (`secret-run` is
   not on PATH; locate it or pass the token another way)

Confirm with `python -m phantom_ai_safety.repair.train_qlora --dry-run` expecting
"model is reachable". The trainer is written against inspected AlignTune signatures, not
invented ones (`PeftConfigData.rank`, not `lora_rank`; `EvaluationConfig` lives in
`aligntune.core.sft.config`). Unresolved risk: AlignTune pins `transformers 5.22.2` /
`trl 1.7.1` while Cohere checkpoints target 4.x; the gate currently fails on auth first.

## Laptop is provisioned and VERIFIED — only the weights are missing

The 4060 laptop is no longer a risk. A real QLoRA step ran on project data:
4-bit NF4 load 27.9s, LoRA r=16 at 5.659% trainable, 2.02 s/step, **peak VRAM 1603 MiB of
8188**, 19.6 MB adapter written and verified non-empty. Full recipe and the two traps are
in `TRAINING-ENVIRONMENT.md`.

Working set (do not deviate without re-testing):
`Python 3.12.16` (via uv, **not** the distro 3.14), `torch 2.13.0+cu130`,
`transformers 5.22.2`, `trl 1.7.1`, `peft 0.21.2`, `bitsandbytes 0.50.2`,
`datasets 5.2.0`, `aligntune 0.1.34`. Venv at `/opt/train312`.

Two traps that cost real time:
1. Distro Python 3.14 breaks AlignTune's `immutables` C extension. Use uv + 3.12.
2. The cu124 index serves stale `torch 2.6.0`, which breaks `peft` import with a
   misleading `BloomPreTrainedModel` error that blames transformers. Let the resolver
   choose torch (it picks 2.13.0+cu130) and peft imports fine.

Paths on the laptop: venv `/opt/train312`; dataset `/mnt/c/Users/Moo/phantom-data/`;
smoke adapters `/opt/qlora-smoke`; log `/opt/provision.log`. Scripts are kept in
`lexsi-work/` (`provision_laptop.sh`, `laptop_train312.sh`, `laptop_torch_fix.sh`,
`qlora_smoke.py`) and copied to `/opt/` on the laptop.

Still unresolved, and untestable until the gate opens: the working stack carries
`transformers 5.22.2` while the Cohere checkpoints were published against 4.x. Fallback if
they do not load is a second 4.x venv training with plain `transformers` + `peft` + `trl`,
which the smoke test already proves works.

## Tooling notes discovered this session

- **Fulcrum's decision service is DOWN.** `moo-ask.mjs predict` returned
  `fallback: true, confidence: 0, choice_index: null` — a dead decision brain. Per
  `FULCRUM-DECISIONS.md` that is "no decision": fail open, do not retry, do not escalate
  to Moo. The `/health` `decision_canary` field should show it.
- **Fulcrum is ON HOLD for public release.** `Projects/Buildtober 2026.md:25` and pending
  decision 2: "fulcrum public or not". Its repo is private Gitea `moo-private/fulcrum`.
  **Do not put Fulcrum into a public repo** — that is Moo's publication decision,
  not ours. Same reasoning rules out HOUND internals (live bounty box, unverified shielded
  research, security/OSINT). Neither addresses Track 2 model alignment anyway.
- **Model router:** `astra` (codex backend) works and was used for the independent red
  team. `opus` fails (`spawnSync claude ENOENT`, CLI missing). `gemini` fails
  (`omniroute` not on PATH). Node script `moo-ask.mjs` exists at
  `C:\Users\Owner\.claude\scripts\moo-ask.mjs`.
- **Shell gotchas:** heredocs into `bash -lc` fail; write a script file and run it.
  Apostrophes inside a PowerShell single-quoted argument close the string early — avoid
  them or use the file tools. `$VAR` set earlier in a `;`-chained command can be eaten by
  the outer shell; use inline paths.

## Remaining work

Not started: slides / demo video (needs Moo's machine and voice), CuratorKIT quality-gate
wiring (real API inspected: `Curator`/`CuratorConfig`/`JSONLReader`, with built-in
adversarial injection via `injection_rate`/`injection_types`), SafeTune leg, HF dataset
and article publishing, model card.

Publishing needs an HF **write** token, same blocker as training.

## Honesty constraints that must survive into the submission

1. The after-numbers are an **upper bound on a self-authored set the repair was tuned
   against**. Use 0.400 (independent families included), never 0.143 alone.
2. Four families fail, not one. `verify_report_claims.py` enforces this.
3. The identity and negation gaps are **not** to be patched with keyword lists.
4. Do not claim a fine-tuned model, HF dataset, or HF model repo exists until it does.
5. `allowlist_masquerade` did NOT reproduce as measured; it stays a source reading.
6. Sponsor repos are source-available, not uniformly open source. AuditKIT Section 1A
   wants written acknowledgement to support@lexsi.ai. **Moo sends it.**
7. Cohere checkpoints are `cc-by-nc-4.0` (non-commercial).

## Cleanup

Nothing running. Two task-owned WSL venvs on **this** box (`~/phantom-eval-venv`,
`~/phantom-train-venv`) can be deleted to reclaim space. Ubuntu WSL on the laptop is a
deliberate install — keep it. No GPU work was ever run on this machine.