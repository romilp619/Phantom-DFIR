"""Report what the committed README actually contains.

Binary-safe: goes through subprocess + explicit utf-8 decode, because redirecting
`git show` through PowerShell produces UTF-16 with a BOM and makes substring tests
lie. That mistake caused a wrong conclusion once already.
"""
from __future__ import annotations

import subprocess

PROBES = [
    "0.273", "0.636", "0.800", "0.400", "0.839", "0.631",
    "Find Evil", "SANS Institute", "attack success", "phantom-safety",
    "Evidence-grounded", "PHANTOM DFIR", "LangGraph",
]

raw = subprocess.run(
    ["git", "show", "HEAD:README.md"], capture_output=True, check=False
).stdout
text = raw.decode("utf-8", errors="replace")

print(f"bytes: {len(raw)}  lines: {text.count(chr(10))}")
print()
for probe in PROBES:
    print(f"  {probe:22s} {'PRESENT' if probe in text else 'ABSENT'}")

print()
print("first 4 lines:")
for line in text.splitlines()[:4]:
    print("  ", line[:78])

print()
print("last 6 lines:")
for line in text.splitlines()[-6:]:
    print("  ", line[:78])
