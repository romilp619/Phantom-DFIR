# Handoff — Lexsi Track 2 submission (phantom-safety)

State as of 2026-11-10 05:05 America/Chicago. Cold-start brief.
Repo: `phantom-safety` (3 commits, `b352283`). Long-form docs in `lexsi-work/`, mirrored to `phantom-safety/docs/`.

## Objective

Winning submission for the Lexsi AI Safety and Alignment Hackathon, Track 2 (AI Red Teaming, Safety and Alignment). Deadline 2026-11-15 11:59 PM AoE. Moo handles registration and submission.

## Headline finding

PHANTOM's advertised adversarial "Skeptic" agent does not verify anything. Its verdict is a threshold on an integer that the audited agent supplies, and **five LLM strategies — including no LLM and a model that refutes everything — produced byte-identical confidences on 300 rows**. The advertised agent-to-agent argument is decorative.

## Done and verified

- 5 defects with file:line, all reproduced against unmodified upstream code (`scripts/smoke_harness.py`)
- Harness drives real upstream code with tool stubs and an injectable LLM
- 8 attack families; baseline over n=400: FCR 0.749, ASR 0.714, DMR 0.427, capability retention 1.000
- Repair (`grounding/verifier.py`): FCR 0.299, ASR 0.143, CR 1.000, McNemar p=1.2e-60, no row regressed
- **Family 8 (`behavioural_mention`) breaks the repair** — written after v2 was frozen, ASR 1.00 before *and* after. The entire residual is this one family. Behavioural relevance is not evidential weight.
- Injection scanner: 15/15 recall, 0/12 false positives, fence neutralisation tested
- Dataset: 2,400 train / 400 held-out, disjoint seed ranges, id overlap 0 (`data/MANIFEST.json`)
- 26 tests pass; working tree clean

## Blocked — needs Moo, about two minutes

**The fine-tuned model does not exist.** All 13 candidate Cohere checkpoints are gated `auto` and return HTTP 401 anonymously (`scripts/probe_hf_access.py`). There is **no Hugging Face credential on this machine**: no `token`, no `stored_tokens`, no HF key in any role file, no vault note. The HF cache contains only anonymously downloaded public models.

I cannot do this part. It needs his account and his assent:

1. Sign in to https://huggingface.co
2. Open https://huggingface.co/CohereLabs/tiny-aya-global and click **Agree and access repository** (Tiny Aya is one 3.35B model, tuned per region; `tiny-aya-global` is the instruction-tuned one)
3. Create a **read** token at https://huggingface.co/settings/tokens
4. Put it somewhere reachable, e.g. `%USERPROFILE%\.secret-roles\hf.env` with `HF_TOKEN=hf_...`. `secret-run` is **not on PATH** — it needs locating or the token passed another way.

Then verify the gate is actually open:

```bash
wsl -d kali-linux
cd /mnt/c/Users/Owner/Downloads/redirect/phantom-safety
$HOME/phantom-eval-venv/bin/python scripts/probe_hf_access.py   # expect USABLE ANONYMOUSLY or a token path
```

## Environment: laptop is ready

- Host: `gaming-laptop` / `desktop-ti68mc5` / **100.96.130.88**, user `Moo`, key `C:\Users\Owner\.dsh\mc-keys\id_rsa`
- **MagicDNS does not resolve from this box** (`desktop-ti68mc5.tail7ffe8f.ts.net` -> no such host). Use the raw Tailscale IP, and note PowerShell mangles `&` in remote commands: pass ssh args as an array, one command per call.
- GPU: **RTX 4060 Laptop, 8188 MiB, driver 621.01**. Verified idle (0%, 3 MiB, 32 C) — only Overwolf loaded.
- **Ubuntu WSL installed** this session (`wsl --install -d Ubuntu --no-launch`), currently Stopped.
- Windows Python 3.13.14 present.

Unresolved risk: AlignTune pins `transformers 5.22.2` / `trl 1.7.1`; the Cohere checkpoints target 4.x. `scripts/check_model_compat.py` is the gate and currently fails only on auth, so **the version question is still unanswered**.

For 8 GB: `tiny-aya-global`, 4-bit NF4 QLoRA, seq 4096, LoRA r=16, microbatch 1 + grad accum + gradient checkpointing. Set `.wslconfig` `memory=12GB` before training.

## Honesty constraints that must survive

1. The after-numbers are an **upper bound on a self-authored set the repair was tuned against**. Say so every time.
2. Family 8 is the only non-tuned measurement; it shows the repair fails. Do not quietly drop it.
3. Do not claim a fine-tuned model, HF dataset, or HF model repo exists until it does.
4. `allowlist_masquerade` did NOT reproduce as measured; it stays a source reading, not a result.
5. Lexsi repos are LSAL source-available, not uniformly open source. AuditKIT Section 1A wants written acknowledgement to support@lexsi.ai. **Moo sends it.**
6. Cohere checkpoints are `cc-by-nc-4.0` (non-commercial).

## Not started

HF dataset publishing, HF article, model card, UI dashboard section (Module E), architecture diagram, demo video, CuratorKIT quality-gate integration, SafeTune leg, CFReDS "Mr. Evil" demo.

## Cleanup

Nothing running. Two WSL venvs on **this** box (`~/phantom-eval-venv`, `~/phantom-train-venv`) are task-owned and can be deleted to reclaim space. Ubuntu WSL on the laptop is a deliberate install — keep it. No GPU work was ever run on this machine, so Moo's session was never disturbed.