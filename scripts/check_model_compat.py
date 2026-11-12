"""Check whether the training stack can actually use a Cohere Labs checkpoint.

This exists because of a specific risk: AlignTune pins `transformers>=5.15,<6`,
but the Tiny Aya / Aya Expanse checkpoints were published against the 4.x line. A
5.x release can drop a legacy architecture path, rename a config key, or change
chat-template handling. Finding that out after a multi-hour download and a failed
training run would cost a day.

This check is deliberately cheap: it reads config and tokenizer files only, a few
megabytes. It does NOT download weights and does NOT run a forward pass. Those are
a separate, explicitly flagged step, because they cost gigabytes.

Exit codes: 0 all checks passed, 1 a check failed, 2 blocked on authentication.
"""
from __future__ import annotations

import json
import os
import sys

CANDIDATES = [
    "CohereLabs/tiny-aya-global",   # primary target at 8 GB VRAM
    "CohereLabs/tiny-aya-base",
    "CohereLabs/aya-expanse-8b",    # upgrade path at 16 GB
]

SAMPLE_MESSAGES = [
    {"role": "user", "content": "Return a JSON verdict object for the claim below."},
]


def report(title: str) -> None:
    print("\n" + "=" * 66)
    print(title)
    print("=" * 66)


def main() -> int:
    report("Training stack versions")
    versions: dict[str, str] = {}
    for name in ("torch", "transformers", "tokenizers", "trl", "peft", "datasets",
                 "accelerate", "bitsandbytes", "aligntune", "curatorkit", "huggingface_hub"):
        try:
            mod = __import__(name)
            versions[name] = getattr(mod, "__version__", "unknown")
        except Exception as exc:  # noqa: BLE001 - report and continue
            versions[name] = f"MISSING ({type(exc).__name__})"
    for k, v in versions.items():
        print(f"  {k:18s} {v}")

    try:
        import transformers
    except Exception as exc:  # noqa: BLE001
        print(f"\nFATAL: transformers not importable: {exc}")
        return 1

    major = int(transformers.__version__.split(".")[0])
    print(f"\n  transformers major line: {major}.x")
    if major >= 5:
        print("  WARNING: 5.x line. The Cohere checkpoints target 4.x. Testing below.")

    report("Token / auth status")
    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    print(f"  HF_TOKEN present: {bool(token)}")
    if not token:
        print("  No HF token in the environment. Public downloads may still work;")
        print("  gated checkpoints will return 401 and need an authenticated token.")

    from transformers import AutoConfig, AutoTokenizer

    failures: list[str] = []
    summary: list[dict] = []

    for repo in CANDIDATES:
        report(f"Checkpoint: {repo}")
        entry: dict = {"repo": repo}
        try:
            cfg = AutoConfig.from_pretrained(repo)
            model_type = getattr(cfg, "model_type", "unknown")
            archs = getattr(cfg, "architectures", None)
            params = getattr(cfg, "num_parameters", None)
            entry.update(model_type=model_type, architectures=archs)
            print(f"  model_type     : {model_type}")
            print(f"  architectures  : {archs}")
            print(f"  vocab_size     : {getattr(cfg, 'vocab_size', 'n/a')}")
            print(f"  max_position   : {getattr(cfg, 'max_position_embeddings', 'n/a')}")
            print(f"  num_parameters : {params}")

            # Does transformers recognise this architecture?
            from transformers.models.auto.modeling_auto import MODEL_FOR_CAUSAL_LM_MAPPING_NAMES
            known = set(MODEL_FOR_CAUSAL_LM_MAPPING_NAMES.values())
            if model_type in known:
                print(f"  causal-LM mapping: FOUND for '{model_type}'")
            else:
                print(f"  causal-LM mapping: NOT FOUND for '{model_type}'  <-- BLOCKER")
                failures.append(f"{repo}: transformers {transformers.__version__} has no "
                                f"causal-LM mapping for model_type '{model_type}'")
        except Exception as exc:  # noqa: BLE001
            msg = f"{type(exc).__name__}: {exc}"
            print(f"  config load FAILED: {msg[:200]}")
            entry["config_error"] = msg[:400]
            if "401" in msg or "gated" in msg.lower() or "authenticat" in msg.lower():
                failures.append(f"{repo}: authentication required")
                summary.append(entry)
                continue
            failures.append(f"{repo}: config load failed")

        try:
            tok = AutoTokenizer.from_pretrained(repo)
            print(f"  tokenizer      : {type(tok).__name__}")
            has_tpl = bool(getattr(tok, "chat_template", None))
            print(f"  chat_template  : {has_tpl}")
            entry["has_chat_template"] = has_tpl
            if has_tpl:
                rendered = tok.apply_chat_template(SAMPLE_MESSAGES, tokenize=False,
                                                   add_generation_prompt=True)
                preview = rendered.replace("\n", "\\n")[:150]
                print(f"  rendered       : {preview}")
                entry["rendered_preview"] = preview
            else:
                print("  WARNING: no chat template; prompts must be hand-built")
        except Exception as exc:  # noqa: BLE001
            msg = f"{type(exc).__name__}: {exc}"
            print(f"  tokenizer FAILED: {msg[:200]}")
            entry["tokenizer_error"] = msg[:400]
            failures.append(f"{repo}: tokenizer load failed")

        summary.append(entry)

    report("Verdict")
    if failures:
        for f in failures:
            print(f"  FAIL: {f}")
        print("\n  Not safe to schedule training yet.")
    else:
        print("  Config, tokenizer and chat template all load on this stack.")

    print("\n  NOT COVERED by this check: weight download, a real forward pass, a LoRA")
    print("  step, and 4-bit quantisation. Those require the weights and a GPU pass.")
    print("  Treat them as a separate gate before any long run.")

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "results", "model_compat.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"versions": versions, "checks": summary, "failures": failures},
                  fh, indent=2)
    print(f"\n  wrote {out}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())