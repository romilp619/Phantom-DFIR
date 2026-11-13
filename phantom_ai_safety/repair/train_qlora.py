"""Module C: QLoRA fine-tune of a Cohere backbone on the safety dataset.

Written against the APIs actually installed in the training venv, discovered by
inspection rather than assumed:

  aligntune.sft            SFTConfig, ModelConfig, DatasetConfig, TrainingConfig,
                           LoggingConfig, EvaluationConfig, SFTTrainerFactory
  PeftConfigData           fields are rank / alpha / dropout, NOT lora_rank
  SFTTrainerFactory        .create_trainer(config) -> trainer with .train(),
                           .evaluate(), .save_model(), .push_to_hub()

Target hardware is an RTX 4060 Laptop with **8188 MiB**, so the configuration is
built for that ceiling and not for the 16 GB box this script happens to be written
on. 4-bit NF4, LoRA r=16, microbatch 1, gradient accumulation, gradient
checkpointing.

`--dry-run` validates the whole pipeline except the parts that need the weights: it
loads the JSONL, renders a sample prompt, builds every config object, and checks the
tokenizer/model config over the network. It downloads no weights and runs no
training step. That is the strongest check possible while the checkpoints are gated.

Why this is blocked: every Cohere Labs checkpoint returns HTTP 401 anonymously, so
this script cannot run until a Hugging Face account has accepted the licence terms
and a read token is available. See scripts/probe_hf_access.py.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(os.path.dirname(HERE))
if PKG_ROOT not in sys.path:
    sys.path.insert(0, PKG_ROOT)

# 8 GB VRAM is the binding constraint. These are deliberately conservative.
DEFAULT_MODEL = "CohereLabs/tiny-aya-global"          # 3.35B, instruction-tuned
UPGRADE_MODEL = "CohereLabs/aya-expanse-8b"           # needs ~16 GB at 4-bit

LORA_TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj",
                       "gate_proj", "up_proj", "down_proj"]


def bnb_4bit_config() -> dict:
    """BitsAndBytesConfig kwargs for QLoRA on an 8 GB card."""
    return {
        "load_in_4bit": True,
        "bnb_4bit_quant_type": "nf4",
        "bnb_4bit_compute_dtype": "bfloat16",
        "bnb_4bit_use_double_quant": True,
    }


def count_jsonl(path: str) -> int:
    with open(path, "r", encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


def build_configs(args) -> tuple:
    """Build the AlignTune config objects. Imports happen here so --help is cheap.

    Import placement matters and was verified against the installed package:
    `EvaluationConfig` and `PeftConfigData` are NOT re-exported from `aligntune.sft`;
    they live in `aligntune.core.sft.config`. `SFTConfig`, `ModelConfig`,
    `DatasetConfig`, `TrainingConfig`, `LoggingConfig` and `TaskType` ARE exported
    from `aligntune.sft`.
    """
    from aligntune.sft import (
        DatasetConfig,
        LoggingConfig,
        ModelConfig,
        SFTConfig,
        TaskType,
        TrainingConfig,
    )
    from aligntune.core.sft.config import EvaluationConfig, PeftConfigData

    peft = PeftConfigData(
        enabled=True,
        variant="qlora",
        rank=args.lora_rank,
        alpha=args.lora_alpha,
        dropout=0.05,
        target_modules=LORA_TARGET_MODULES,
        bias="none",
    )
    model = ModelConfig(
        name_or_path=args.model,
        max_seq_length=args.max_seq_length,
        peft=peft,
        peft_enabled=True,
        lora_rank=args.lora_rank,
        quantization=bnb_4bit_config(),
        gradient_checkpointing=True,
        use_gradient_checkpointing=True,
        use_unsloth=False,
        trust_remote_code=False,
        device_map="auto",
    )
    train_ds = DatasetConfig(
        name=args.train,
        train_split="train",
        messages_column="messages",
        task_type=TaskType.SFT,
    )
    eval_ds = None
    if args.eval and os.path.exists(args.eval):
        eval_ds = DatasetConfig(
            name=args.eval,
            train_split="train",
            messages_column="messages",
            task_type=TaskType.SFT,
        )
    train_cfg = TrainingConfig(
        per_device_batch_size=args.micro_batch,
        gradient_accumulation_steps=args.grad_accum,
        epochs=args.epochs,
        max_steps=args.max_steps,
        learning_rate=args.lr,
        warmup_ratio=0.03,
        lr_scheduler="cosine",
        optimizer="adamw_torch",
        bf16=True,
        fp16=False,
        max_grad_norm=1.0,
        eval_interval=args.eval_interval,
        save_interval=args.save_interval,
        dataloader_num_workers=0,
        remove_unused_columns=False,
        packing=False,
        completion_only_loss=True,
    )
    logging_cfg = LoggingConfig(
        output_dir=args.output_dir,
        run_name=args.run_name,
        loggers=[],
        report_to="none",
        save_strategy="steps",
    )
    eval_cfg = EvaluationConfig(
        compute_perplexity=True,
        compute_rouge=True,
        compute_bleu=True,
        compute_meteor=False,
        compute_bertscore=False,
        compute_semantic_similarity=False,
        max_samples_for_quality_metrics=50,
    )
    return (
        SFTConfig(model=model, dataset=train_ds, eval_dataset=eval_ds,
                  train=train_cfg, logging=logging_cfg, evaluation=eval_cfg),
        model, train_ds, train_cfg,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--train", default="data/train.jsonl")
    ap.add_argument("--eval", default="data/heldout.jsonl")
    ap.add_argument("--output-dir", default="runs/phantom-safety-qlora")
    ap.add_argument("--run-name", default="phantom-safety-qlora")
    ap.add_argument("--micro-batch", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=16)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--lora-rank", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--max-seq-length", type=int, default=4096)
    ap.add_argument("--eval-interval", type=int, default=50)
    ap.add_argument("--save-interval", type=int, default=200)
    ap.add_argument("--dry-run", action="store_true",
                    help="validate configs and data without loading weights")
    args = ap.parse_args()

    print("=" * 78)
    print("QLoRA SAFETY FINE-TUNE")
    print("=" * 78)

    # --- data gate (no weights needed) ---
    if not os.path.exists(args.train):
        print(f"FATAL: training data not found: {args.train}")
        print("       run: python -m phantom_ai_safety.repair.dataset --outdir data")
        return 1
    n_train = count_jsonl(args.train)
    n_eval = count_jsonl(args.eval) if os.path.exists(args.eval) else 0
    print(f"  train rows : {n_train}  ({args.train})")
    print(f"  eval rows  : {n_eval}  ({args.eval})")

    with open(args.train, "r", encoding="utf-8") as fh:
        sample = json.loads(fh.readline())
    roles = [m["role"] for m in sample["messages"]]
    print(f"  sample roles: {roles}")
    assert roles == ["system", "user", "assistant"], "unexpected message structure"
    # Render length matters on an 8 GB card: tail truncation would cut the target.
    chars = sum(len(m["content"]) for m in sample["messages"])
    print(f"  sample chars: {chars} (~{chars // 4} tokens)")

    total_steps = args.max_steps if args.max_steps > 0 else int(
        n_train / max(1, args.micro_batch * args.grad_accum) * args.epochs)
    print(f"  effective batch: {args.micro_batch} x {args.grad_accum} = "
          f"{args.micro_batch * args.grad_accum}")
    print(f"  planned steps  : {total_steps}")

    config, model_cfg, ds_cfg, train_cfg = build_configs(args)
    print(f"\n  resolved model      : {model_cfg.name_or_path}")
    print(f"  quantisation        : {model_cfg.quantization}")
    print(f"  max_seq_length      : {model_cfg.max_seq_length}")
    print(f"  lora rank/alpha     : {model_cfg.peft.rank}/{model_cfg.peft.alpha}")
    print(f"  target modules      : {model_cfg.peft.target_modules}")
    print(f"  config types        : {type(config).__name__} "
          f"ok={type(config).__name__ == 'SFTConfig'}")

    if args.dry_run:
        print("\n" + "-" * 78)
        print("DRY RUN: configs built and data validated. No weights loaded, no "
              "training step run.")
        print("-" * 78)
        # Tokenizer/model *config* only. This is what surfaces the gating error.
        try:
            from transformers import AutoConfig, AutoTokenizer
            print("  fetching model config (no weights)...")
            cfg = AutoConfig.from_pretrained(args.model, trust_remote_code=False)
            print(f"  ok: model_type={getattr(cfg, 'model_type', '?')} "
                  f"vocab={getattr(cfg, 'vocab_size', '?')}")
            tok = AutoTokenizer.from_pretrained(args.model, trust_remote_code=False)
            print(f"  ok: tokenizer={type(tok).__name__} "
                  f"chat_template={'yes' if getattr(tok, 'chat_template', None) else 'NO'}")
            print("\n  RESULT: model is reachable. Ready to train (drop --dry-run).")
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"\n  model config fetch FAILED: {type(exc).__name__}")
            print(f"  {str(exc)[:400]}")
            print("\n  RESULT: BLOCKED before training. If this is a 401 gated repository, "
                  "accept the licence on the model page and supply an HF token.")
            return 2

    # --- real run ---
    from aligntune.sft import SFTTrainerFactory
    trainer = SFTTrainerFactory().create_trainer(config)
    print("\n  trainer created; starting training")
    trainer.train()
    trainer.save_model(args.output_dir)
    print(f"\n  saved to {args.output_dir}")
    print("  NOTE: adapters only. Report the run hash and steps in the write-up.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())