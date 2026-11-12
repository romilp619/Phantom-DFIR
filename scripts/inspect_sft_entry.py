"""Focused inspection of the AlignTune SFT entry points and CuratorKIT config.

Narrow follow-up to inspect_stack_api.py: I need the exact call signature for a
supervised fine-tune run and the exact CuratorConfig fields, because the trainer has
to call them rather than approximate them.
"""
from __future__ import annotations

import inspect


def show(label: str, obj) -> None:
    try:
        print(f"{label}: {str(inspect.signature(obj))[:1200]}")
    except Exception:  # noqa: BLE001
        print(f"{label}: (no signature)")


def main() -> int:
    print("=" * 78)
    print("ALIGNTUNE SFT ENTRY POINTS")
    print("=" * 78)
    try:
        import aligntune.sft as sft
        print("aligntune.sft public:", [n for n in dir(sft) if not n.startswith("_")])
        for n in dir(sft):
            if n.startswith("_"):
                continue
            obj = getattr(sft, n)
            if inspect.isclass(obj) or inspect.isfunction(obj):
                show(f"  aligntune.sft.{n}", obj)
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    print("\n" + "=" * 78)
    print("ALIGNTUNE CLI CONFIG BUILDERS")
    print("=" * 78)
    try:
        from aligntune.cli import build_sft_config, create_trainer_from_config, parse_args
        show("build_sft_config", build_sft_config)
        show("create_trainer_from_config", create_trainer_from_config)
        show("parse_args", parse_args)
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    print("\n" + "=" * 78)
    print("ALIGNTUNE CORE SFT / MODEL LOADER")
    print("=" * 78)
    for modname in ("aligntune.core.sft", "aligntune.core.model_loader", "aligntune.data"):
        try:
            mod = __import__(modname, fromlist=["*"])
            pub = [n for n in dir(mod) if not n.startswith("_")]
            print(f"\n[{modname}] public: {pub[:40]}")
            for n in pub:
                obj = getattr(mod, n)
                if (inspect.isclass(obj) or inspect.isfunction(obj)) and getattr(obj, "__module__", "").startswith("aligntune"):
                    show(f"   * {n}", obj)
        except Exception as exc:  # noqa: BLE001
            print(f"\n[{modname}] failed: {type(exc).__name__}: {exc}")

    print("\n" + "=" * 78)
    print("CURATORKIT CONFIG AND CURATOR")
    print("=" * 78)
    try:
        from curatorkit import Curator, CuratorConfig, JSONLReader, DataSample, CuratorResult
        show("Curator.__init__", Curator.__init__)
        for m in ("run", "curate", "process"):
            if hasattr(Curator, m):
                show(f"Curator.{m}", getattr(Curator, m))
        fields = getattr(CuratorConfig, "__dataclass_fields__", {})
        print(f"\nCuratorConfig fields ({len(fields)}):")
        for name, f in fields.items():
            print(f"   {name}: {str(f.type)[:60]} = {f.default if f.default is not inspect.Parameter.empty else '<required>'}")
        print("\nDataSample fields:", list(getattr(DataSample, "__dataclass_fields__", {})))
        print("JSONLReader fields:", list(getattr(JSONLReader, "__dataclass_fields__", {})) or "(not a dataclass)")
        show("JSONLReader.__init__", JSONLReader.__init__)
        print("CuratorResult fields:", list(getattr(CuratorResult, "__dataclass_fields__", {})))
    except Exception as exc:  # noqa: BLE001
        print(f"  failed: {type(exc).__name__}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())