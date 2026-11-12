"""Tests for the CuratorKIT hardening guards.

Each test corresponds to one reproduced defect in the upstream toolkit. The guards exist
so the pipeline fails loudly where the toolkit fails silently; therefore the tests assert
that the guard RAISES on the dangerous configuration, not merely that it returns a warning.
"""
from __future__ import annotations

import pytest

from phantom_ai_safety.curation.guards import (
    KNOWN_FORMATS,
    CurationConfigError,
    cross_check_formats,
    resolve_format,
    safe_clean_transforms,
    validate_config,
    verify_run,
)


# ---------------------------------------------------------- defect 1: format strings

def test_container_name_is_rejected_with_guidance():
    """'jsonl' upstream rejects 100% of rows silently. The guard must refuse it."""
    with pytest.raises(CurationConfigError) as e:
        resolve_format("jsonl")
    msg = str(e.value)
    assert "alpaca" in msg, "the error must name the value that works"
    assert "100%" in msg, "the error must explain what upstream does silently"


@pytest.mark.parametrize("bad", ["json", "jsonlines", "csv", "parquet", "nonsense"])
def test_unknown_formats_raise(bad):
    with pytest.raises(CurationConfigError):
        resolve_format(bad)


@pytest.mark.parametrize("good", KNOWN_FORMATS)
def test_known_formats_pass(good):
    assert resolve_format(good) == good


def test_format_is_case_and_space_insensitive():
    assert resolve_format("  AlPaCa ") == "alpaca"


def test_default_format_is_alpaca_when_unspecified():
    assert resolve_format(None) == "alpaca"


def test_non_sft_format_is_an_error_for_sft_corpus():
    """prompt_only cannot carry a response, so it is wrong for a supervised corpus."""
    with pytest.raises(CurationConfigError) as e:
        validate_config(format="prompt_only")
    assert "supervised" in str(e.value)


# ------------------------------------------------- defect 2: marker preservation

def test_default_cleaning_is_refused_when_markers_matter():
    """The upstream default (strip_html=True) must not silently pass the guard."""
    with pytest.raises(CurationConfigError) as e:
        validate_config(format="alpaca", keep_markers=True)  # strip_html defaults True
    assert "strip_html" in str(e.value)
    assert "marker" in str(e.value).lower()


def test_explicit_strip_html_false_is_accepted():
    rep = validate_config(
        format="alpaca",
        clean_transforms={"strip_html": False},
        keep_markers=True,
    )
    assert rep.ok
    assert any("strip_html" in c for c in rep.checked)


def test_safe_clean_transforms_disables_strip_html():
    assert safe_clean_transforms(keep_markers=True) == {"strip_html": False}
    assert safe_clean_transforms(keep_markers=False) == {"strip_html": True}


def test_markers_can_be_deliberately_sacrificed():
    """A corpus with no markers may legitimately keep the default cleaning."""
    rep = validate_config(
        format="alpaca",
        clean_transforms={"strip_html": True},
        keep_markers=False,
    )
    assert rep.ok


# ------------------------------------------------------- defect 3: injection no-op

def test_injection_rate_without_types_is_refused():
    with pytest.raises(CurationConfigError) as e:
        validate_config(
            format="alpaca",
            clean_transforms={"strip_html": False},
            injection_rate=0.10,
            injection_types=None,
        )
    assert "injection_types" in str(e.value)


def test_injection_rate_with_types_is_accepted():
    rep = validate_config(
        format="alpaca",
        clean_transforms={"strip_html": False},
        injection_rate=0.10,
        injection_types=["instruction_override"],
    )
    assert rep.ok


def test_zero_injection_rate_is_fine():
    rep = validate_config(
        format="alpaca",
        clean_transforms={"strip_html": False},
        injection_rate=0.0,
    )
    assert rep.ok


# ------------------------------------------------------------ post-run verification

class _FakeSample:
    def __init__(self, instruction: str = "", input: str = ""):
        self.instruction = instruction
        self.input = input


def test_verify_run_raises_when_every_row_rejected():
    """The exact symptom we hit: 0 passed, N rejected, no reason given."""
    with pytest.raises(CurationConfigError) as e:
        verify_run(passed=[], rejected=[object()] * 3300)
    assert "100%" in str(e.value) or "every row" in str(e.value).lower()


def test_verify_run_raises_when_markers_vanished():
    """A run reporting success while having deleted all structure must fail loudly."""
    samples = [_FakeSample("plain text no markers") for _ in range(50)]
    with pytest.raises(CurationConfigError) as e:
        verify_run(passed=samples, rejected=[], expected_markers=True)
    assert "strip_html" in str(e.value)


def test_verify_run_passes_when_markers_survive():
    samples = [
        _FakeSample("<<UNTRUSTED_EVIDENCE id=EV-1>>\nsvc\t882", "claim text")
        for _ in range(50)
    ]
    rep = verify_run(passed=samples, rejected=[], expected_markers=True)
    assert rep.ok
    assert any("marker_retention=50/50" in c for c in rep.checked)


def test_verify_run_warns_on_partial_marker_loss():
    samples = (
        [_FakeSample("<<UNTRUSTED_EVIDENCE id=EV-1>>") for _ in range(10)]
        + [_FakeSample("no marker here") for _ in range(90)]
    )
    rep = verify_run(passed=samples, rejected=[], expected_markers=True)
    assert rep.ok, "partial loss is a warning, not a failure"
    assert rep.warnings, "partial marker loss must be surfaced"


def test_verify_run_without_marker_expectation_is_quiet():
    samples = [_FakeSample("plain") for _ in range(10)]
    rep = verify_run(passed=samples, rejected=[], expected_markers=False)
    assert rep.ok


# ------------------------------------------------------------- drift protection

def test_declared_formats_match_installed_toolkit():
    """If curatorkit is installed, our mirror of its enum must not have drifted.

    Skips silently when the toolkit is absent so the suite runs anywhere.
    """
    info = cross_check_formats()
    if not info.get("available"):
        pytest.skip("curatorkit not installed in this environment")
    assert info["in_sync"], (
        f"KNOWN_FORMATS drifted from curatorkit.DataFormat: "
        f"missing={info['missing_from_declared']} extra={info['not_installed']}"
    )