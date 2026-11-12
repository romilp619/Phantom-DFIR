"""Process-isolated bridge to the phantom-guard Rust scanner.

`phantom_ai_safety.evidence_scanner.scanner` is the reference implementation: it runs
in-process and is what the test suite exercises. This module is the hardened path for
running the same rules across a boundary an artifact cannot cross.

Why a subprocess and not a Python import
----------------------------------------
The threat model is "untrusted recovered text reaches the analyzer". A pure-Python
scanner shares an interpreter with everything the evidence later touches. That gives
injected content a theoretical surface it should never have: rebind a name, poison a
module cache, exhaust memory the caller needed. None of that is a live exploit in the
current code, and none of it is necessary to accept.

Inside a separate process the only channel back is JSON on stdout. The guard holds no
state between artifacts, so one hostile artifact cannot influence the scan of the next.

Why this is not the default
---------------------------
It is slower per artifact (a process spawn, unless a batch is used) and it requires a
built binary. Tests and development use the in-process scanner; production and the
red-team evaluation use this. `available()` reports whether the binary is present so
callers can degrade explicitly rather than silently.

Equivalence is enforced, not assumed: `tests/test_rust_guard.py` runs both
implementations over the same corpus and requires identical findings.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Candidate locations for the compiled binary, checked in order. The environment
# variable wins so a deployment can pin an exact build.
_ENV_VAR = "PHANTOM_GUARD_BIN"

_REPO_ROOT = Path(__file__).resolve().parents[2]

_CANDIDATES = (
    _REPO_ROOT / "phantom-guard" / "target" / "release" / "phantom-guard",
    _REPO_ROOT / "phantom-guard" / "target" / "release" / "phantom-guard.exe",
    _REPO_ROOT / "phantom-guard" / "target" / "debug" / "phantom-guard",
    _REPO_ROOT / "phantom-guard" / "target" / "debug" / "phantom-guard.exe",
)


class GuardUnavailable(RuntimeError):
    """Raised when the compiled guard cannot be located or executed."""


class GuardError(RuntimeError):
    """Raised when the guard runs but fails, so a caller never mistakes failure for safety."""


def binary_path() -> Path | None:
    """Locate the guard binary, or None if it has not been built."""
    override = os.environ.get(_ENV_VAR)
    if override:
        p = Path(override)
        return p if p.is_file() else None
    for candidate in _CANDIDATES:
        if candidate.is_file():
            return candidate
    # Fall back to PATH, for an installed build.
    found = shutil.which("phantom-guard")
    return Path(found) if found else None


def available() -> bool:
    """True when a guard binary can be executed."""
    return binary_path() is not None


def manifest(timeout: float = 10.0) -> dict:
    """Return the guard's identity manifest: version, rule count, rule fingerprint.

    A report should record this so a verdict can be tied to a specific guard build.
    """
    exe = binary_path()
    if exe is None:
        raise GuardUnavailable(
            "phantom-guard binary not found. Build it with "
            "`cargo build --release` in the phantom-guard directory, or set "
            f"{_ENV_VAR} to its path."
        )
    proc = subprocess.run(
        [str(exe), "manifest"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise GuardError(f"manifest failed (exit {proc.returncode}): {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def self_test(timeout: float = 30.0) -> tuple[bool, str]:
    """Run the guard's built-in cases. Returns (ok, output)."""
    exe = binary_path()
    if exe is None:
        raise GuardUnavailable("phantom-guard binary not found")
    proc = subprocess.run(
        [str(exe), "self-test"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


@dataclass
class GuardFinding:
    """One manipulation signal, as reported by the Rust guard."""
    artifact_id: str
    artifact_sha256: str
    category: str
    severity: str
    explanation: str
    matched_text: str
    char_offset: int
    rule_pattern: str


@dataclass
class GuardResult:
    """The guard's result for one artifact, shaped like the Python ScanResult."""
    artifact_id: str
    artifact_sha256: str
    length: int
    highest_severity: str | None
    is_manipulated: bool
    findings: list[GuardFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "length": self.length,
            "highest_severity": self.highest_severity,
            "is_manipulated": self.is_manipulated,
            "findings": [
                {
                    "artifact_id": f.artifact_id,
                    "artifact_sha256": f.artifact_sha256,
                    "category": f.category,
                    "severity": f.severity,
                    "explanation": f.explanation,
                    "matched_text": f.matched_text,
                    "char_offset": f.char_offset,
                    "rule_pattern": f.rule_pattern,
                }
                for f in self.findings
            ],
        }


def _result_from_dict(d: dict) -> GuardResult:
    return GuardResult(
        artifact_id=d["artifact_id"],
        artifact_sha256=d["artifact_sha256"],
        length=d["length"],
        highest_severity=d.get("highest_severity"),
        is_manipulated=bool(d["is_manipulated"]),
        findings=[
            GuardFinding(
                artifact_id=f["artifact_id"],
                artifact_sha256=f["artifact_sha256"],
                category=f["category"],
                severity=f["severity"],
                explanation=f["explanation"],
                matched_text=f["matched_text"],
                char_offset=f["char_offset"],
                rule_pattern=f["rule_pattern"],
            )
            for f in d.get("findings", [])
        ],
    )


def scan_artifact(artifact_id: str, text: str, snippet: int = 120, timeout: float = 30.0) -> GuardResult:
    """Scan one artifact through the process boundary."""
    exe = binary_path()
    if exe is None:
        raise GuardUnavailable("phantom-guard binary not found")
    payload = json.dumps({"id": artifact_id, "text": text})
    proc = subprocess.run(
        [str(exe), "--snippet", str(snippet), "scan"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        # A failed scan must never be read as a clean scan.
        raise GuardError(
            f"guard scan failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}"
        )
    return _result_from_dict(json.loads(proc.stdout))


def scan_evidence(
    items: list[tuple[str, str]], snippet: int = 120, timeout: float = 120.0
) -> list[GuardResult]:
    """Scan a batch of (artifact_id, text) pairs in a single process.

    Preferred over repeated `scan_artifact` calls: one spawn for the whole batch, and
    no state carries between artifacts because the guard holds none.
    """
    exe = binary_path()
    if exe is None:
        raise GuardUnavailable("phantom-guard binary not found")
    if not items:
        return []
    payload = json.dumps([{"id": a, "text": t} for a, t in items])
    proc = subprocess.run(
        [str(exe), "--snippet", str(snippet), "batch"],
        input=payload,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise GuardError(
            f"guard batch failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}"
        )
    return [_result_from_dict(d) for d in json.loads(proc.stdout)]


def summarize(results: list[GuardResult]) -> dict:
    """Aggregate counts, matching the Python module's summary shape."""
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {
        "artifacts_scanned": len(results),
        "artifacts_manipulated": sum(1 for r in results if r.is_manipulated),
        "total_findings": sum(len(r.findings) for r in results),
        "by_category": by_category,
        "by_severity": by_severity,
        "implementation": "rust",
        "boundary": "process",
    }