# Handoff — Lexsi Track 2 submission (phantom-safety)

State as of 2026-11-10 07:25 America/Chicago. Cold-start brief.
Repo `phantom-safety`, 6 commits, HEAD `99ab418`, 45 tracked files, working tree clean.
Long-form docs in `lexsi-work/`, mirrored into `phantom-safety/docs/`.

## Objective

Winning submission for the Lexsi AI Safety and Alignment Hackathon, Track 2 (AI Red
Teaming, Safety and Alignment). Deadline 2026-11-15 11:59 PM AoE. Moo registers and
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

## Done and verified (re-run all of this in one pass, 2026-11-10)

| Check | Command | Result |
|---|---|---|
| Findings reproduce against real upstream code | `python scripts/smoke_harness.py` | all checks reproduced |
| Scanner recall and false positives | `python scripts/validate_scanner.py` | all checks passed |
| Test suite | `pytest tests/ -q` | **29 passed** |
| Write-up figures vs stored results | `python scripts/verify_report_claims.py` | all figures match |
| Round-trip integrity gate | `python -m phantom_ai_safety.repair.dataset --outdir data` | VERIFIED, 2800 rows |

Numbers, n=400, seed 1729, paired exact McNemar p=1.24e-60, no row regressed:

| Metric | Before | After |
|---|---:|---:|
| Accuracy vs gold | 0.375 | 0.875 |
| False-confirm rate | 0.749 | 0.299 |
| Attack success rate | 0.714 | 0.143 |
| Dangerous-miss rate | 0.427 | 0.000 |
| Capability retention | 1.000 | 1.000 |
| Citation coverage on confirmed rows | 0/267 | 167/167 |

**Held-out replication (disjoint seed 90000, n=400) reproduces all five exactly.** The
result is therefore no longer only tuned-against. Generator overfitting is still not
excluded, because both splits come from the same eight generators.

## The repair fails, and that is the strongest part of the story

Family 8 (`behavioural_mention`) was written **after verifier v2 was frozen**, making it
the one non-tuned measurement. Four real behavioural artifacts (malfind, netscan,
dlllist, cmdline) each merely *name* the file while describing ordinary activity. The
repair confirms all 50 rows: **ASR 1.00 before and after**. The entire residual
after-score is this family.

Behavioural relevance is not evidential weight. A third rule was deliberately **not**
shipped, because one written against this family would be fitted to it and prove
nothing. `tests/test_core.py::test_KNOWN_BYPASS_behavioural_mention` asserts the bypass
exists, so the suite fails loudly when it is fixed.

## Two silent defects found in our own harness

The held-out run first disagreed with the tuned run, which was impossible if both
measured the same verifier. The rendered prompt was losing structured evidence metadata,
and each loss changed what was measured while still printing plausible numbers:

1. **`plugin` dropped** -> nothing could be behavioural -> reported capability retention
   0.660 on *untouched control rows*.
2. **Artifact identity collapsed into the evidence id** -> five records of one PID
   looked like five artifacts -> reported `count_inflation` ASR 1.00.

Neither raised an exception. The fix is structural: the fence carries `id`, `artifact`
and `plugin`; a missing field is a hard error; one shared parser; and `check_roundtrip`
re-runs the verifier on every rebuilt row at build time (2,800 rows) plus three tests.
Reported in `docs/RESULTS-COMPARISON.md` and section 5 of the HF write-up.

## Blocked — needs Moo, about two minutes

**No fine-tuned model exists.** All 13 candidate Cohere checkpoints are gated
(`gated: "auto"`, HTTP 401 anonymous) and there is **no Hugging Face credential on this
machine** — no `token`, no `stored_tokens`, no HF key in any role file, no vault note.
The cache holds only anonymously downloaded public models.

I cannot do this part: it needs his account and his assent to a licence.

1. Sign in at https://huggingface.co
2. Open https://huggingface.co/CohereLabs/tiny-aya-global and click **Agree and access repository**
3. Create a **read** token at https://huggingface.co/settings/tokens
4. Put it at `%USERPROFILE%\.secret-roles\hf.env` as `HF_TOKEN=hf_...` (`secret-run` is
   not on PATH; locate it or pass the token another way)

Then confirm the gate is open:

```bash
wsl -d kali-linux
cd /mnt/c/Users/Owner/Downloads/redirect/phantom-safety
$HOME/phantom-train-venv/bin/python -m phantom_ai_safety.repair.train_qlora --dry-run
# expect "RESULT: model is reachable. Ready to train (drop --dry-run)."
```

The trainer is **written against inspected AlignTune signatures, not invented ones**
(`PeftConfigData.rank`, not `lora_rank`; `EvaluationConfig` lives in
`aligntune.core.sft.config`, not `aligntune.sft`). `--dry-run` validates data and every
config object, then fails at the gate with a clear message. Nothing else needs writing
before training.

Unresolved risk: AlignTune pins `transformers 5.22.2` / `trl 1.7.1`; the Cohere
checkpoints target the 4.x line. `scripts/check_model_compat.py` is the gate and the
version question is **still unanswered** because it fails on auth first.

## Environment: laptop ready and idle

- `gaming-laptop` / `desktop-ti68mc5` / **100.96.130.88**, user `Moo`, key
  `C:\Users\Owner\.dsh\mc-keys\id_rsa`
- **MagicDNS does not resolve from this box**; use the raw Tailscale IP. PowerShell
  mangles `&` in remote commands: pass ssh args as an array, one command per call.
  Heredocs into `bash -lc` also fail; write a script file and run it instead.
- GPU **RTX 4060 Laptop, 8188 MiB, driver 621.01**, verified idle (0%, 3 MiB, 32 C)
- **Ubuntu WSL installed** this session, currently Stopped
- For 8 GB: `tiny-aya-global`, 4-bit NF4 QLoRA, seq 4096, LoRA r=16, microbatch 1 +
  grad accum 16, gradient checkpointing. Set `.wslconfig memory=12GB` before training.

## Remaining work (none of it needs the token except training)

Not started: Module E dashboard section, architecture diagram for slides (ASCII version
exists at `docs/ARCHITECTURE.md`), demo video, CuratorKIT quality-gate wiring (real API
inspected: `Curator`/`CuratorConfig`/`JSONLReader`, and it has built-in adversarial
injection via `injection_rate`/`injection_types`), SafeTune leg, HF dataset publishing,
HF article publishing, model card (premature until a model exists).

Publishing needs an HF **write** token, same blocker as training.

## Honesty constraints that must survive into the submission

1. The after-numbers are an **upper bound on a self-authored set the repair was tuned
   against** — say so every time. The disjoint-seed replication strengthens this but does
   not remove it, since both splits use the same eight generators.
2. Family 8 is the only non-tuned measurement and it shows the repair failing. Do not
   quietly drop it.
3. Do not claim a fine-tuned model, HF dataset, or HF model repo exists until it does.
4. `allowlist_masquerade` did NOT reproduce as measured; it stays a source reading.
5. Lexsi repos are LSAL source-available, not uniformly open source. AuditKIT Section 1A
   wants written acknowledgement to support@lexsi.ai. **Moo sends it.**
6. Cohere checkpoints are `cc-by-nc-4.0` (non-commercial).

## Cleanup

Nothing running. Two task-owned WSL venvs on **this** box (`~/phantom-eval-venv`,
`~/phantom-train-venv`) can be deleted to reclaim space. Ubuntu WSL on the laptop is a
deliberate install — keep it. No GPU work was ever run on this machine, so Moo's session
was never disturbed.