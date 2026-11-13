"""CuratorKIT hardening: guard rails for the three toolkit defects found in our run.

The upstream toolkit (0.1.24) has three behaviours that fail silently in ways that damage
a forensic/safety pipeline. Each was reproduced on real data, not inferred from reading:

1. **Invalid `format` string drops the whole corpus.**
   `format="jsonl"` is not a DataFormat member. It does not raise; it falls back to UNKNOWN
   and rejects 100% of rows, with `RejectedSample` carrying no reason. A builder sees
   `output_count=0` and an empty stage table with nothing to act on.

2. **Default `TextCleaner` deletes evidence markers.**
   `strip_html` removes tag-shaped text. In this dataset the angle-bracket markers are the
   evidence anchors (`<<UNTRUSTED_EVIDENCE id=...>>`), so the default removes the semantic
   structure the model is meant to learn, then reports a clean pass rate of 1.000.
   Measured: 0/1900 rows retained markers by default, 1900/1900 with the fix.

3. **`injection_rate` without `injection_types` is a silent no-op.**
   Setting `injection_rate=0.10` produced identical counts to 0.0, no injected rows, and an
   empty `diagnostics` dict. There is no warning that the rate had no effect.

This module does not fork CuratorKIT. It wraps it: validate before the run, verify after,
and fail loudly where the toolkit fails silently. Pure stdlib plus the toolkit import, so it
is testable without a model or network.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# Valid DataFormat values, mirrored so validation does not need the package at import time.
# Kept in sync with curatorkit.detection.DataFormat; a test asserts they agree when the
# package is installed.
KNOWN_FORMATS: tuple[str, ...] = (
    "alpaca",
    "sharegpt",
    "preference",
    "implicit_preference",
    "unpaired_preference",
    "grpo",
    "prompt_only",
    "pretrain",
    "unknown",
)

# Formats that cannot carry a supervised instruction/response pair. Selecting one for a
# safety SFT corpus is a configuration error worth catching early.
NON_SFT_FORMATS: frozenset[str] = frozenset({"prompt_only", "pretrain", "unknown"})


class CurationConfigError(ValueError):
    """Raised when a CuratorKIT configuration would fail silently."""


@dataclass
class CurationGuardReport:
    """What the guard checked, and what it found. Returned for logging."""
    checked: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checked": self.checked,
            "warnings": self.warnings,
            "errors": self.errors,
        }


def resolve_format(fmt: str | None) -> str:
    """Validate a format string, failing loudly instead of silently rejecting every row.

    Defect 1. An unrecognised value raises with the valid choices listed, because the
    upstream fallback (UNKNOWN, reject all, no reason) is the worst possible response.
    """
    if fmt is None:
        return "alpaca"
    norm = str(fmt).strip().lower()
    if norm in ("jsonl", "json", "jsonlines"):
        raise CurationConfigError(
            f"format={fmt!r} is a file container, not a CuratorKIT DataFormat. "
            f"Upstream accepts it silently and then rejects 100% of rows with no reason. "
            f"Use one of: {', '.join(KNOWN_FORMATS)}. "
            f"For chat to instruction/response data, use 'alpaca'."
        )
    if norm not in KNOWN_FORMATS:
        raise CurationConfigError(
            f"unknown format {fmt!r}; valid values are: {', '.join(KNOWN_FORMATS)}"
        )
    return norm


def requires_marker_preservation(format_name: str) -> bool:
    """True when the dataset's own structure must survive cleaning.

    Evidence-grounded corpora carry angle-bracket sentinels. Any SFT format used for them
    must disable strip_html, or the sentinels are silently deleted.
    """
    return format_name not in NON_SFT_FORMATS


def safe_clean_transforms(keep_markers: bool = True) -> dict[str, bool]:
    """Cleaning transforms that preserve evidence markers (defect 2)."""
    transforms = {"strip_html": not keep_markers}
    return transforms


def validate_config(
    format: str | None = None,
    injection_rate: float = 0.0,
    injection_types: Iterable[str] | None = None,
    clean_transforms: dict[str, bool] | None = None,
    keep_markers: bool = True,
) -> CurationGuardReport:
    """Check a CuratorKIT configuration against all three known silent failures.

    Raises CurationConfigError on anything that would corrupt or silently discard data.
    Returns a report of warnings for recoverable-but-worth-knowing conditions.
    """
    rep = CurationGuardReport()

    # ---- defect 1: format
    fmt = resolve_format(format)
    rep.checked.append(f"format={fmt}")
    if fmt in NON_SFT_FORMATS:
        rep.errors.append(
            f"format={fmt!r} cannot carry supervised instruction/response pairs, "
            f"which a safety SFT corpus requires"
        )

    # ---- defect 2: marker deletion
    ct = dict(clean_transforms or {})
    strip_html = ct.get("strip_html", True)  # upstream default is True
    rep.checked.append(f"strip_html={strip_html}")
    if keep_markers and strip_html and requires_marker_preservation(fmt):
        rep.errors.append(
            "strip_html is enabled (the upstream default) but this corpus carries "
            "angle-bracket evidence markers. TextCleaner removes tag-shaped text, so "
            "every marker would be deleted while the run still reports success. "
            "Pass clean_transforms={'strip_html': False}."
        )

    # ---- defect 3: injection_rate with no types
    if injection_rate and injection_rate > 0:
        types = list(injection_types or [])
        rep.checked.append(f"injection_rate={injection_rate} types={types}")
        if not types:
            rep.errors.append(
                f"injection_rate={injection_rate} with no injection_types is a silent "
                f"no-op upstream: the run produces identical output to rate 0.0 and an "
                f"empty diagnostics dict. Either set injection_types or set the rate to 0."
            )
    else:
        rep.checked.append("injection_rate=0 (no injection requested)")

    if not rep.ok:
        raise CurationConfigError("; ".join(rep.errors))
    return rep


def verify_run(
    passed: list[Any],
    rejected: list[Any],
    expected_markers: bool = True,
    sampled: int = 200,
) -> CurationGuardReport:
    """Post-run assertions that the toolkit cannot be trusted to make itself.

    Checks the outcome rather than the configuration: did rows survive, and did the
    evidence structure survive with them.
    """
    rep = CurationGuardReport()
    n_pass, n_rej = len(passed), len(rejected)
    rep.checked.append(f"passed={n_pass} rejected={n_rej}")

    if n_pass == 0 and n_rej > 0:
        rep.errors.append(
            f"every row was rejected ({n_rej} rejected, 0 passed) and the toolkit did not "
            f"say why. Check the format string first: a container name like 'jsonl' "
            f"rejects 100% of rows silently."
        )
        raise CurationConfigError("; ".join(rep.errors))

    if expected_markers and passed:
        sample = passed[:sampled]
        with_marker = 0
        for s in sample:
            text = " ".join(str(getattr(s, k, "") or "") for k in ("instruction", "input"))
            if "<" in text and ">" in text:
                with_marker += 1
        rate = with_marker / len(sample) if sample else 0.0
        rep.checked.append(f"marker_retention={with_marker}/{len(sample)}")
        if rate == 0.0:
            rep.errors.append(
                "no surviving row retains an evidence marker. TextCleaner.strip_html "
                "almost certainly removed them. The run will look successful while having "
                "destroyed the training signal: pass clean_transforms={'strip_html': False}."
            )
        elif rate < 0.5:
            rep.warnings.append(
                f"only {with_marker}/{len(sample)} rows retain evidence markers "
                f"({rate:.0%}); cleaning may be removing structure from part of the corpus"
            )

    if not rep.ok:
        raise CurationConfigError("; ".join(rep.errors))
    return rep


def cross_check_formats() -> dict:
    """Confirm KNOWN_FORMATS still matches the installed package's DataFormat enum.

    Guards against this module drifting from reality when the toolkit is upgraded.
    """
    try:
        from curatorkit.detection import DataFormat
    except Exception as exc:  # pragma: no cover - only when toolkit absent
        return {"available": False, "reason": str(exc)}
    installed = {m.value for m in DataFormat}
    declared = set(KNOWN_FORMATS)
    return {
        "available": True,
        "installed": sorted(installed),
        "declared": sorted(declared),
        "missing_from_declared": sorted(installed - declared),
        "not_installed": sorted(declared - installed),
        "in_sync": installed == declared,
    }