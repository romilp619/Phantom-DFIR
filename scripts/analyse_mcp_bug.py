"""Extract and analyse the mcpserver Tool bug from the repository.

The module raises NameError: name 'Tool' is not defined at import time, so the MCP server
cannot start. This script pulls the exact source and the exact call sites so a bug report
can cite line numbers instead of describing the fault from memory.

Read-only apart from writing the extracted copy under artifacts/.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

REVS = {"original 3005762": "3005762", "integrated HEAD": "HEAD", "remote origin/main": "origin/main"}
PATH = "mcpserver/mcp_server.py"

out_dir = Path("artifacts")
out_dir.mkdir(exist_ok=True)

for label, rev in REVS.items():
    raw = subprocess.run(
        ["git", "show", f"{rev}:{PATH}"], capture_output=True
    ).stdout
    if not raw:
        print(f"{label}: no such blob")
        continue
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    print(f"=== {label} ===")
    print(f"  {len(lines)} lines, {len(raw)} bytes")

    imports = [
        (i + 1, l) for i, l in enumerate(lines)
        if re.match(r"^\s*(import|from)\s", l)
    ]
    tool_calls = [
        (i + 1, l) for i, l in enumerate(lines)
        if re.search(r"\bTool\s*\(", l)
    ]
    defines_tool = any(
        re.match(r"^\s*(class\s+Tool\b|def\s+Tool\b|Tool\s*=)", l) for l in lines
    )

    print(f"  imports: {len(imports)}")
    for n, l in imports:
        print(f"    {n:5d}: {l.strip()[:90]}")
    print(f"  'Tool(' call sites: {len(tool_calls)}")
    for n, l in tool_calls[:8]:
        print(f"    {n:5d}: {l.strip()[:90]}")
    print(f"  defines Tool locally: {defines_tool}")
    tool_re = re.compile(r"\bTool\b")
    imports_tool = any(tool_re.search(l) for _, l in imports)
    print(f"  imports anything named Tool: {imports_tool}")
    print()

    if rev == "HEAD":
        (out_dir / "mcp_server_extracted.py").write_text(text, encoding="utf-8")
        print(f"  wrote artifacts/mcp_server_extracted.py for reference")
    print()