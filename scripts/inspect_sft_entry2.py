"""Final API-shape inspection: factory methods, PEFT and evaluation config fields."""
from __future__ import annotations

import inspect


def fields_of(cls) -> list[str]:
    f = getattr(cls, "__dataclass_fields__", {})
    out = []
    for name, fd in f.items():
        default = fd.default
        if default is inspect.Parameter.empty or type(default).__name__ == "_MISSING_TYPE":
            default = "<required>"
        else:
            default = repr(default)[:40]
        out.append(f"{name}: {str(fd.type)[:48]} = {default}")
    return out


def main() -> int:
    print("=" * 78)
    print("SFTTrainerFactory methods")
    print("=" * 78)
    try:
        from aligntune.sft import SFTTrainerFactory
        for n in dir(SFTTrainerFactory):
            if n.startswith("_"):
                continue
            obj = getattr(SFTTrainerFactory, n)
            if callable(obj):
                try:
                    print(f"  {n}{str(inspect.signature(obj))[:400]}")
                except Exception:  # noqa: BLE001
                    print(f"  {n}: (no sig)")
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    print("\n" + "=" * 78)
    print("SFTTrainerBase methods (truncated)")
    print("=" * 78)
    try:
        from aligntune.sft import SFTTrainerBase
        print(" ", [n for n in dir(SFTTrainerBase) if not n.startswith("_")][:60])
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    print("\n" + "=" * 78)
    print("CONFIG FIELD LISTS")
    print("=" * 78)
    try:
        from aligntune.core.sft.config import (
            DatasetConfig, EvaluationConfig, LoggingConfig, ModelConfig,
            PeftConfigData, SFTConfig, TrainingConfig,
        )
        for cls in (PeftConfigData, EvaluationConfig, DatasetConfig, TrainingConfig):
            print(f"\n--- {cls.__name__} ---")
            for line in fields_of(cls)[:45]:
                print("   ", line)
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    print("\n" + "=" * 78)
    print("ENUMS")
    print("=" * 78)
    try:
        from aligntune.sft import BackendType, PrecisionType, TaskType
        for e in (BackendType, PrecisionType, TaskType):
            print(f"  {e.__name__}: {[m.value for m in e]}")
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())