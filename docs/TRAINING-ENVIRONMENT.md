# Training environment: verified recipe for the RTX 4060 laptop

Verified 2026-11-10 by running an actual QLoRA training step, not by installing packages and
assuming they work. This file exists because the working combination is not the obvious one,
and rediscovering it under deadline pressure would be expensive.

## The machine

- Host `DESKTOP-TI68MC5`, Tailscale `100.96.130.88`, user `Moo`
- GPU **RTX 4060 Laptop, 8188 MiB**, driver 621.01
- Ubuntu **26.04.1 LTS** under WSL2, CUDA reachable from inside WSL with no driver work
- 6 cores, `.wslconfig` capped at `memory=12GB`, `swap=4GB`

Access notes, because all three cost time:

- **MagicDNS does not resolve from the main box.** Use the raw Tailscale IP.
- **The remote login shell is PowerShell, not cmd.** `if exist` fails; use PowerShell syntax.
- **Do not build ssh commands by nesting quotes.** Write a `.sh` file, `scp` it over, run it.
  Heredocs into `bash -lc` and escaped quotes inside a PowerShell string both fail.

## The two traps

### Trap 1: the distro Python is too new

Ubuntu 26.04 ships **Python 3.14.4**. PyTorch does publish `cp314` wheels, so this looks
fine at first. But AlignTune pulls `immutables`, whose C extension fails to compile against
3.14 (`compilation terminated`, even with `build-essential` installed).

**Fix:** do not fight it. Use `uv` to provision Python 3.12:

```
pip install uv
uv venv --python 3.12 /opt/train312
```

### Trap 2: the cu124 index serves a stale torch, and that breaks peft

Installing torch from `https://download.pytorch.org/whl/cu124` on Python 3.12 yields
**torch 2.6.0**, and with it `peft` fails to import:

```
ModuleNotFoundError: Could not import module 'BloomPreTrainedModel'
```

That is misleading: it reads as a transformers 5 incompatibility, but the actual cause is
the torch version. AlignTune's own resolver pulls **torch 2.13.0+cu130** and then `peft`
0.21.2 imports cleanly against the same `transformers 5.22.2`.

**Fix:** install from the default index and let the resolver choose, or install `aligntune`
first and let it bring torch with it. Do not pin the cu124 index.

This is worth reporting upstream: a builder following the obvious CUDA-index instruction
lands in a broken import chain, and the error message points at the wrong package.

## The verified working set

```
Python        3.12.16        (via uv; NOT the distro 3.14)
torch         2.13.0+cu130
transformers  5.22.2
trl           1.7.1          (AlignTune's pin)
peft          0.21.2
bitsandbytes  0.50.2
datasets      5.2.0
aligntune     0.1.34
```

`aligntune.sft` entry points confirmed importable: `SFTConfig`, `SFTTrainerFactory`,
`ModelConfig`, `DatasetConfig`, `TrainingConfig`, plus `PeftConfigData` and
`EvaluationConfig` from `aligntune.core.sft.config`. Note `PeftConfigData` uses `rank`,
not `lora_rank`, and `EvaluationConfig` is **not** re-exported from `aligntune.sft`.

## Paths on the laptop

| What | Path |
|---|---|
| Training venv | `/opt/train312` |
| Dataset | `/mnt/c/Users/Moo/phantom-data/` (train.jsonl 9.9 MB, heldout.jsonl 1.6 MB) |
| Smoke adapters | `/opt/qlora-smoke` |
| Provision log | `/opt/provision.log` |

## Verified training performance

Measured with `qlora_smoke.py` on a 135M ungated model, real project data, 4-bit NF4,
LoRA r=16, sequence length 2048, batch 1 with gradient accumulation:

| Measurement | Value |
|---|---|
| 4-bit load time | 27.9 s |
| VRAM after load | 107 MiB |
| Trainable fraction | 5.659% (4,884,480 of 86,315,328) |
| Throughput | 2.02 s/step |
| **Peak VRAM** | **1,603 MiB of 8,188 MiB** |
| Adapter written | 19.6 MB, verified non-empty |

The peak is the important number: it leaves over 6.5 GB free, so the real 3.35B target at
4096 sequence length has room. These figures are for an 86M model and are **not** a
prediction for the real run; they establish that the plumbing works and that there is
headroom.

## What is still blocking the real run

Only the model weights. All 13 candidate Cohere Labs checkpoints are gated (`gated: "auto"`)
and return HTTP 401 anonymously, and there is no Hugging Face credential on this machine.

Once a token exists:

```
export HF_TOKEN=hf_...
/opt/train312/bin/python -m phantom_ai_safety.repair.train_qlora --model CohereLabs/tiny-aya-global --train /mnt/c/Users/Moo/phantom-data/train.jsonl --dry-run
```

The dry run should print `RESULT: model is reachable`, after which dropping `--dry-run`
starts the real run. **Unresolved risk:** the working stack carries `transformers 5.22.2`,
and the Cohere checkpoints were published against the 4.x line. Whether they load under 5.x
cannot be tested until the gate opens. If they do not, the fallback is a second venv on
transformers 4.x without AlignTune, training with plain `transformers` + `peft` + `trl`,
which is the path this smoke test already proves works.
