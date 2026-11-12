"""Discover the REAL AlignTune / CuratorKIT APIs before writing a trainer.

The project spec is explicit: integrate the sponsor libraries without inventing APIs.
This script prints the actual public surface of what is installed, so the training
script is written against signatures that exist rather than signatures I assumed.

Read-only: imports packages and inspects them. No training, no downloads.
"""
from __future__ import annotations

import inspect
import pkgutil


def banner(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def describe_module(mod, name: str) -> None:
    public = [n for n in dir(mod) if not n.startswith("_")]
    classes, funcs = [], []
    for n in public:
        obj = getattr(mod, n)
        if inspect.isclass(obj):
            try:
                sig = str(inspect.signature(obj))
            except Exception:
                sig = "(no signature)"
            classes.append((n, sig))
        elif inspect.isfunction(obj):
            try:
                sig = str(inspect.signature(obj))
            except Exception:
                sig = "(no signature)"
            funcs.append((n, sig))
    print(f"\n[{name}] classes:")
    for n, sig in classes:
        print(f"  {n}{sig[:220]}")
    print(f"[{name}] functions:")
    for n, sig in funcs:
        print(f"  {n}{sig[:220]}")
    if not classes and not funcs:
        print(f"  (no classes/functions; public names: {public[:40]})")


def main() -> int:
    banner("PACKAGE INVENTORY")
    for pkg in ("aligntune", "curatorkit"):
        try:
            mod = __import__(pkg)
            print(f"  {pkg}: version={getattr(mod, '__version__', '?')}  file={mod.__file__}")
        except Exception as exc:  # noqa: BLE001
            print(f"  {pkg}: IMPORT FAILED: {type(exc).__name__}: {exc}")

    banner("ALIGNTUNE TOP LEVEL")
    try:
        import aligntune
        describe_module(aligntune, "aligntune")
        print("\n[aligntune] submodules:")
        for m in pkgutil.iter_modules(aligntune.__path__):
            print("   ", m.name)
    except Exception as exc:  # noqa: BLE001
        print(f"  import failed: {exc}")

    banner("ALIGNTUNE TASK ENTRIES (sft / dpo / qlora)")
    import aligntune
    for sub in ("core", "trainers", "tasks", "cli", "configs"):
        try:
            mod = __import__(f"aligntune.{sub}", fromlist=["*"])
            print(f"\n-- aligntune.{sub} --")
            print("   public:", [n for n in dir(mod) if not n.startswith("_")][:50])
        except Exception as exc:  # noqa: BLE001
            print(f"\n-- aligntune.{sub}: {type(exc).__name__} --")

    banner("TRL SFTTRAINER SIGNATURE (what AlignTune ultimately drives)")
    try:
        from trl import SFTTrainer, SFTConfig
        print("SFTTrainer:", str(inspect.signature(SFTTrainer))[:900])
        print("\nSFTConfig fields:", [f for f in getattr(SFTConfig, "__dataclass_fields__", {})][:60])
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    banner("PEFT / QUANTISATION")
    try:
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        print("LoraConfig:", str(inspect.signature(LoraConfig))[:600])
        print("prepare_model_for_kbit_training:", str(inspect.signature(prepare_model_for_kbit_training))[:300])
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    banner("TRANSFORMERS QUANT + MODEL LOADING")
    try:
        import transformers
        print("transformers:", transformers.__version__)
        from transformers import BitsAndBytesConfig, AutoModelForCausalLM, AutoTokenizer
        print("BitsAndBytesConfig:", str(inspect.signature(BitsAndBytesConfig))[:600])
        print("AutoModelForCausalLM.from_pretrained params:",
              [p for p in inspect.signature(AutoModelForCausalLM.from_pretrained).parameters][:30])
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    banner("CURATORKIT")
    try:
        import curatorkit
        describe_module(curatorkit, "curatorkit")
    except Exception as exc:  # noqa: BLE001
        print(f"  curatorkit import failed: {type(exc).__name__}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())