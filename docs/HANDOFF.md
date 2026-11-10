# Handoff — Lexsi Track 2 submission (phantom-safety)

State as of 2026-11-10 03:55 America/Chicago. Session was long; this is the cold-start brief.

## Objective

Prepare a winning submission for the Lexsi AI Safety and Alignment Hackathon, Track 2 (AI Red Teaming, Safety and Alignment). Deadline 2026-11-15 11:59 PM AoE. Moo handles registration and submission manually.

## Where things are

- Derived repo: `C:\Users\Owner\Downloads\redirect\phantom-safety\` (git, 1 commit `1219666`)
- Upstream clone: `C:\Users\Owner\Downloads\redirect\Phantom-DFIR\` — **content-unmodified**, verify with the digest note in the repo README
- Research briefs and long-form docs: `C:\Users\Owner\Downloads\redirect\lexsi-work\` (also copied into `phantom-safety/docs/`)
- Two WSL venvs: `~/phantom-eval-venv` (harness, pytest) and `~/phantom-train-venv` (AlignTune stack)

## Done and verified

- Audit of the upstream verification layer: 5 defects with file:line, all reproduced against real code (`scripts/smoke_harness.py`, 25 tests pass)
- Harness runs real upstream code with tool stubs and an injectable LLM
- Baseline over 350 synthetic rows: FCR 0.691, ASR 0.667, DMR 0.427, capability retention 1.000
- **Headline finding: the Skeptic's LLM has zero decision authority.** Five strategies (none, echo, confirm-all, refute-all, garbage) produced byte-identical confidences on 300 rows
- Repair (grounding/verifier.py v2): FCR 0.000, ASR 0.000, CR 1.000, McNemar p=1.2e-60
- v1 of the repair was broken by a self-authored attack (`citation_stuffing`, ASR 1.00); v2 closes it — this arc is the strongest part of the story
- Injection scanner: 15/15 recall, 0/12 false positives, fence neutralisation tested

## Blocked

**The fine-tuned model does not exist.** All Cohere Labs checkpoints are GATED and return HTTP 401 anonymously:

```
CohereLabs/tiny-aya-global, tiny-aya-base, aya-expanse-8b  -> 401 gated repo
```

To unblock, a human must (1) sign in to Hugging Face, (2) accept the licence terms at
`https://huggingface.co/CohereLabs/tiny-aya-global`, (3) provide a read token. No HF token exists in
`%USERPROFILE%\.secret-roles`, `secret-run` is not on PATH, and there is no HF cache.

Training target decision is ALSO unresolved: Moo said the RTX 4060 laptop is on, but this machine has
an RTX 5070 Ti (16 GB). The recommended model changes with the answer:
- 8 GB (4060): `CohereLabs/tiny-aya-global`, 4-bit NF4 QLoRA, seq 4096, LoRA r=16
- 16 GB (5070 Ti): `CohereLabs/aya-expanse-8b` at 2048-4096 context is the stronger result

Verified incompatibility risk: AlignTune pins `transformers 5.22.2` / `trl 1.7.1`; the Cohere
checkpoints target the 4.x line. `scripts/check_model_compat.py` is the gate — it currently fails only
on auth, so the version question is STILL UNANSWERED.

## Next action (cold-startable)

```bash
# after the token exists
wsl -d kali-linux
export HF_TOKEN=<token>   # use secret-run, never paste into a transcript
cd /mnt/c/Users/Owner/Downloads/redirect/phantom-safety
$HOME/phantom-train-venv/bin/python scripts/check_model_compat.py   # must print no failures
```
Then: load the model, one templated generate, one LoRA step. Only then schedule training.

## Honesty constraints that must survive

1. The 1.000 after-score is an **upper bound on a self-authored set the repair was tuned against**. Say so every time. An independent held-out set is required for an unbiased number.
2. Do not claim a fine-tuned model, a HF dataset, or a HF model repo exists until it does.
3. `allowlist_masquerade` did NOT reproduce as measured; it stays labelled a source reading, not a result.
4. Lexsi repos are LSAL source-available, not uniformly open source. AuditKIT Section 1A wants written acknowledgement to support@lexsi.ai. Moo sends it.
5. Cohere checkpoints are `cc-by-nc-4.0` (non-commercial). State it.

## Not started

HF dataset publishing, HF article, model card, UI dashboard section, architecture diagram, demo video,
CuratorKIT quality-gate integration, SafeTune leg.