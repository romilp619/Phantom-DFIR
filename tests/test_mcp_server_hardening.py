"""Regression tests: MCP tool arguments can never become shell commands.

The MCP server's tools take their arguments from an MCP client, which is a model.
Earlier revisions interpolated those arguments into `subprocess.run(..., shell=True)`
strings, so a "pid" or a file path containing shell syntax ran as a command. These
tests pin the fix: arguments are passed as literal argv entries with no shell.

No forensic tool is needed. Tiny stub executables stand in for vol, strings and fls
and simply echo the arguments they received.
"""
from __future__ import annotations

import inspect
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(os.name == "nt", reason="stub tools are POSIX shell scripts")

from mcpserver import mcp_server as m  # noqa: E402

ECHO_ARGS = '#!/bin/sh\nfor a in "$@"; do echo "ARG<$a>"; done\n'
MANY_LINES = (
    '#!/bin/sh\n'
    'i=0; while [ $i -lt 50000 ]; do echo "row $i powershell APP.EXE-0A1B2C3D.pf"; i=$((i+1)); done\n'
)


def _stub(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.fixture()
def tools(tmp_path, monkeypatch):
    """Stub vol/strings/fls on PATH, and a marker file no payload may create."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    vol = _stub(bin_dir, "vol", ECHO_ARGS)
    _stub(bin_dir, "strings", ECHO_ARGS)
    _stub(bin_dir, "fls", ECHO_ARGS)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(m, "VOL3_CMD", str(vol))
    monkeypatch.chdir(tmp_path)
    return tmp_path / "INJECTED_MARKER"


def _payloads(marker: Path) -> list[str]:
    """Shell syntax that used to execute when placed in a tool argument."""
    return [
        f"x.img'; touch '{marker}'; echo '",
        f"x.img; touch {marker}",
        f"$(touch {marker})",
        f"`touch {marker}`",
        f"x.img | touch {marker}",
        f"x.img && touch {marker}",
        f"x.img\ntouch {marker}",
    ]


MEMORY_TOOLS = ["get_process_list", "get_cmdline", "get_malfind", "get_dll_list",
                "get_services"]
DISK_TOOLS = ["get_disk_strings", "get_mft_deleted_files", "get_prefetch"]


@pytest.mark.parametrize("tool", MEMORY_TOOLS)
def test_memory_tool_filepath_is_never_executed(tools, tool):
    for payload in _payloads(tools):
        m.TOOL_DISPATCH[tool]({"filepath": payload})
        assert not tools.exists(), f"{tool} executed shell syntax from filepath: {payload!r}"


@pytest.mark.parametrize("tool", DISK_TOOLS)
def test_disk_tool_path_is_never_executed(tools, tool):
    for payload in _payloads(tools):
        m.TOOL_DISPATCH[tool]({"disk_path": payload})
        assert not tools.exists(), f"{tool} executed shell syntax from disk_path: {payload!r}"


def test_registry_key_argument_is_passed_intact(tools):
    for payload in _payloads(tools):
        m.get_registry_run_keys(payload)
        assert not tools.exists()
    raw = m.get_registry_run_keys("x.img")["raw"]
    assert "ARG<--key>" in raw
    assert "ARG<Software\\Microsoft\\Windows\\CurrentVersion\\Run>" in raw


def test_filepath_reaches_the_tool_as_one_literal_argument(tools):
    payload = f"x.img'; touch '{tools}'; echo '"
    out = m._run_vol3(payload, "windows.pslist")
    assert f"ARG<{payload}>" in out
    assert not tools.exists()


@pytest.mark.parametrize("tool", ["get_malfind", "get_cmdline", "get_dll_list"])
def test_non_numeric_pid_is_rejected(tools, tool):
    for bad in (f"1; touch {tools} #", f"1 $(touch {tools})", "1 --dump", "abc", "-5", True):
        with pytest.raises(ValueError):
            m.TOOL_DISPATCH[tool]({"filepath": "x.img", "pid": bad})
    assert not tools.exists()


def test_numeric_pid_is_passed_through(tools):
    assert m._pid_args(1234) == ["--pid", "1234"]
    assert m._pid_args("1234") == ["--pid", "1234"]
    assert m._pid_args(None) == [] and m._pid_args(0) == [] and m._pid_args("") == []
    out = m._run_vol3("x.img", "windows.cmdline", m._pid_args(77))
    assert "ARG<--pid>" in out and "ARG<77>" in out


def test_path_cannot_be_read_as_an_option(tools):
    assert m._safe_path("-rf") == "./-rf"
    assert m._safe_path("/cases/a b.img") == "/cases/a b.img"
    for bad in ("", None, 7, "a\x00b"):
        with pytest.raises(ValueError):
            m._safe_path(bad)


def test_disk_timeline_does_not_execute_arguments(tools, tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    _stub(bin_dir, "log2timeline.py", ECHO_ARGS)
    _stub(bin_dir, "psort.py", ECHO_ARGS)
    evil = tmp_path / f"disk.E01; touch {tools.name}"
    evil.write_bytes(b"")
    out_dir = tmp_path / f"out; touch {tools.name}"
    out_dir.mkdir()
    result = m.get_disk_timeline(str(evil), str(out_dir))
    assert result["timeline_built"] is False
    assert not tools.exists() and not (tmp_path / tools.name).exists()


def test_head_lines_stops_early_and_filters(tools, tmp_path):
    _stub(tmp_path / "bin", "strings", MANY_LINES)
    assert len(m._head_lines(["strings", "x"], 25, 30)) == 25
    hits = m._head_lines(["strings", "x"], 5, 30, match=m._PREFETCH_LINE)
    assert len(hits) == 5 and all(h.endswith(".pf") for h in hits)
    result = m.get_disk_strings("x.img")
    assert "powershell" in result["hits"] and result["total_keywords_found"] == 1


def test_no_shell_true_remains_in_the_server():
    source = inspect.getsource(m)
    assert "shell=True" not in source
    assert "os.system(" not in source


def test_http_server_binds_to_localhost_by_default():
    assert inspect.signature(m.run_http_server).parameters["host"].default == "127.0.0.1"


def test_results_are_still_json_serialisable(tools):
    for tool in MEMORY_TOOLS:
        json.dumps(m.TOOL_DISPATCH[tool]({"filepath": "x.img"}), default=str)
