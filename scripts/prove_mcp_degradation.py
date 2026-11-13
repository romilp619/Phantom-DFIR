"""Prove whether mcpserver/mcp_server.py degrades gracefully when `mcp` is absent.

The module wraps its MCP SDK import in try/except ImportError and sets MCP_AVAILABLE=False
with a printed warning. That reads as "we handle a missing dependency". But TOOL_DEFINITIONS
at line 644 is module-level code that calls Tool(...) twenty times with no guard, so if the
import failed the module cannot be imported at all.

This script makes that concrete: it blocks `mcp`, imports the module, and reports what
actually happened. If the try/except worked, the import succeeds with MCP_AVAILABLE False.
"""
from __future__ import annotations

import subprocess

TREES = {
    "original 3005762": "/mnt/c/Users/Owner/Downloads/redirect/phantom-safety/artifacts/phaseE/orig",
    "integrated HEAD": "/mnt/c/Users/Owner/Downloads/redirect/phantom-safety/artifacts/phaseE/repo",
}
PY = "/root/phantom-eval-venv/bin/python"

# Child program: block `mcp`, then try to import the module.
CHILD = r'''
import sys, importlib.abc, importlib.machinery

class Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "mcp" or fullname.startswith("mcp."):
            raise ImportError("mcp blocked for this test")
        return None

sys.meta_path.insert(0, Blocker())
sys.argv = ["mcp_server.py"]

try:
    mod = importlib.import_module("mcpserver.mcp_server")
except NameError as e:
    print("RESULT: NameError ->", e)
    print("VERDICT: the try/except did not help; module-level code crashed")
except ImportError as e:
    print("RESULT: ImportError ->", e)
    print("VERDICT: failed on some other import, not conclusive")
else:
    avail = getattr(mod, "MCP_AVAILABLE", "missing")
    print("RESULT: imported ok, MCP_AVAILABLE =", avail)
    if avail is False:
        print("VERDICT: degraded gracefully as the try/except intends")
    else:
        print("VERDICT: imported but MCP_AVAILABLE is not False - unexpected")
'''

for label, tree in TREES.items():
    print(f"=== {label} ===")
    proc = subprocess.run(
        ["wsl", "-d", "kali-linux", "--", "bash", "-lc",
         f"cd {tree} && {PY} -c {CHILD!r}"],
        capture_output=True, text=True, timeout=180,
    )
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    for line in out.splitlines():
        print(f"  {line}")
    if not out and err:
        print(f"  stderr: {err.splitlines()[-1][:160]}")
    print()