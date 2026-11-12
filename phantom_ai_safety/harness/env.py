"""Harness that drives the REAL PHANTOM verification code against synthetic evidence.

Why this exists: the upstream pipeline needs Volatility, Sleuth Kit and a memory
image, none of which are present. But the verification and scoring logic under
test is a pure function of text and structured objects, so it can be exercised
directly once the collection layer is replaced with stubs and the LLM is made
injectable.

Two guarantees this module tries to keep:

1. The code under test is imported from the upstream clone, unmodified. We do not
   reimplement `correlation.confidence.score`, `agents.skeptic._enforce_evidence_rules`
   or `agents.skeptic._rule_based_skeptic`. Divergent copies would invalidate the
   whole experiment.
2. Nothing here writes to the upstream repository, and nothing shells out to a
   forensic tool.

Paths are configurable through PHANTOM_ROOT so the same harness runs from WSL
(/mnt/c/...) and from Windows.
"""
from __future__ import annotations

import os
import sys
import types
from typing import Any, Callable, Optional

WSL_PHANTOM_ROOT = "/mnt/c/Users/Owner/Downloads/redirect/Phantom-DFIR"
WIN_PHANTOM_ROOT = r"C:\Users\Owner\Downloads\redirect\Phantom-DFIR"


def phantom_root() -> str:
    """Resolve the upstream clone location, overridable via PHANTOM_ROOT."""
    env = os.environ.get("PHANTOM_ROOT")
    if env:
        return env
    return WIN_PHANTOM_ROOT if os.name == "nt" else WSL_PHANTOM_ROOT


def add_phantom_to_path() -> str:
    """Put the upstream clone on sys.path so `import agents.skeptic` works."""
    root = phantom_root()
    if not os.path.isdir(root):
        raise RuntimeError(f"PHANTOM_ROOT does not exist: {root}")
    if root not in sys.path:
        sys.path.insert(0, root)
    return root


_STUB_MODULES = (
    "tools.vol3_tools",
    "tools.vol2_tools",
    "tools.memory_triage",
    "tools.trusted_resources",
)


def _make_stub_module(name: str) -> types.ModuleType:
    """A module whose every attribute lookup returns an empty-output function.

    Any Volatility plugin wrapper therefore returns an empty string, which is the
    honest representation of "this plugin produced no output". Callers pass their
    synthetic evidence in directly instead of asking the collector for it.
    """
    mod = types.ModuleType(name)

    def _stub(*_args: Any, **_kwargs: Any) -> str:
        return ""

    def __getattr__(attr: str) -> Any:  # PEP 562 module-level fallback
        if attr.startswith("__"):
            raise AttributeError(attr)
        return _stub

    mod.__dict__["__getattr__"] = __getattr__
    mod.__dict__["__stub__"] = True
    return mod


def install_tool_stubs() -> None:
    """Replace the forensic tool modules before anything imports them.

    Safe to call more than once. Modules already imported are left alone, because
    swapping an imported module mid-run would silently change behaviour between
    experiments.
    """
    for name in _STUB_MODULES:
        if name not in sys.modules:
            sys.modules[name] = _make_stub_module(name)


def make_fake_llm(strategy: str) -> Optional[Callable[[str], str]]:
    """Build an LLM stand-in for the Skeptic's `SKEPTIC_PROMPT | llm` chain.

    LangChain coerces a bare callable into a RunnableLambda, so the returned
    function receives the fully formatted prompt text and returns the model's
    "completion". Strategies exist to test whether the Skeptic's verdict has any
    decision authority:

    - "none"          -> returns None; `run_skeptic` takes the rule-based path.
    - "always_refute" -> the model denies every hypothesis regardless of evidence.
    - "always_confirm"-> the model confirms every hypothesis regardless of evidence.
    - "garbage"       -> invalid JSON, forcing the exception fallback path.
    - "echo_count"    -> the model agrees with the count, i.e. a well-behaved model.
    """
    if strategy == "none":
        return None

    if strategy == "garbage":
        def _garbage(_prompt: str) -> str:
            return "I am unable to comply with that request."
        return _garbage

    if strategy in ("always_refute", "always_confirm"):
        verdict = "REFUTED" if strategy == "always_refute" else "CONFIRMED"

        def _constant(prompt: str) -> str:
            # Recover the hypothesis ids the prompt carries so the fake answer is
            # shaped like a real one. The ids are the only thing we need to mirror.
            import json as _json
            import re as _re
            ids = _re.findall(r'"id"\s*:\s*"([^"]+)"', prompt)
            return _json.dumps(
                [
                    {
                        "id": h,
                        "verdict": verdict,
                        "reason": f"model holds {verdict} on every hypothesis",
                        "additional_checks": [],
                    }
                    for h in ids
                ]
            )
        return _constant

    if strategy == "echo_count":
        def _echo(prompt: str) -> str:
            import json as _json
            import re as _re
            ids = _re.findall(r'"id"\s*:\s*"([^"]+)"', prompt)
            required = _re.findall(r'"required_verdict"\s*:\s*"([^"]+)"', prompt)
            out = []
            for idx, h in enumerate(ids):
                verdict = required[idx] if idx < len(required) else "NEEDS_MORE"
                out.append(
                    {
                        "id": h,
                        "verdict": verdict,
                        "reason": "model agrees with the supplied source count",
                        "additional_checks": [],
                    }
                )
            return _json.dumps(out)
        return _echo

    raise ValueError(f"unknown LLM strategy: {strategy}")


def load_skeptic(strategy: str = "echo_count"):
    """Import the upstream Skeptic module and install the requested LLM stand-in.

    Import is deferred until the tool stubs are in place, matching the order the
    real application uses.
    """
    add_phantom_to_path()
    install_tool_stubs()

    import agents.skeptic as skeptic  # noqa: E402  (import after stubs, by design)

    if strategy == "none":
        skeptic.llm = None
    else:
        skeptic.llm = make_fake_llm(strategy)
    return skeptic


def load_confidence():
    """Import the upstream confidence scorer, which only depends on config."""
    add_phantom_to_path()
    install_tool_stubs()
    import correlation.confidence as confidence  # noqa: E402
    return confidence


def describe() -> dict:
    """Environment fingerprint, recorded alongside every run for reproducibility."""
    info: dict = {
        "phantom_root": phantom_root(),
        "phantom_root_exists": os.path.isdir(phantom_root()),
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }
    try:
        import hashlib

        digest = hashlib.sha256()
        for rel in ("correlation/confidence.py", "agents/skeptic.py", "agents/evidence.py"):
            path = os.path.join(phantom_root(), rel)
            with open(path, "rb") as fh:
                digest.update(fh.read())
        info["source_digest_sha256"] = digest.hexdigest()
    except OSError as exc:  # pragma: no cover - only when the clone is missing
        info["source_digest_error"] = str(exc)
    return info