"""Independently verify the audit's core structural claims.

Checks, all read-only:
 1. Every file in the original tree (3005762) is present in the integrated tree (2fa27b6).
 2. Those files are BYTE-IDENTICAL (blob SHA) except the 2 declared conflicts.
 3. The 86/88 identity claim.
 4. Which AI-module paths are additive.
 5. Python files parse in both trees.

Written because an audit nobody re-ran is just a claim.
"""
from __future__ import annotations

import subprocess
import sys

ORIG = "3005762"
INTEG = "2fa27b6"
KNOWN_CONFLICTS = {".gitignore", "README.md"}


def run(*args: str) -> str:
    return subprocess.run(list(args), capture_output=True, text=True).stdout


def tree(rev: str) -> dict[str, str]:
    """path -> blob sha for every file in the commit."""
    out = run("git", "ls-tree", "-r", rev)
    entries = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) >= 3 and parts[1] == "blob":
            entries[path] = parts[2]
    return entries


orig = tree(ORIG)
integ = tree(INTEG)

print(f"original {ORIG}: {len(orig)} files")
print(f"integrated {INTEG}: {len(integ)} files")
print()

missing = sorted(set(orig) - set(integ))
common = sorted(set(orig) & set(integ))
identical = [p for p in common if orig[p] == integ[p]]
differing = [p for p in common if orig[p] != integ[p]]
additive = sorted(set(integ) - set(orig))

print("=== 1. original files missing from integrated tree ===")
if missing:
    for p in missing:
        print(f"  MISSING: {p}")
else:
    print("  none - every original file survives")

print()
print("=== 2. common files: identical vs differing ===")
print(f"  common paths      : {len(common)}")
print(f"  byte-identical    : {len(identical)}")
print(f"  differing         : {len(differing)}")
for p in differing:
    declared = "declared conflict" if p in KNOWN_CONFLICTS else "*** UNDECLARED ***"
    print(f"    {p}  ({declared})")

print()
print("=== 3. the 86/88 claim ===")
print(f"  original files kept identical: {len(identical)} of {len(orig)}")
print(f"  differs from claimed 86/88 by: {len(identical) - 86}")

print()
print("=== 4. additive AI-module paths ===")
print(f"  additive count: {len(additive)}")
prefixes: dict[str, int] = {}
for p in additive:
    top = p.split("/")[0] if "/" in p else "(root file)"
    prefixes[top] = prefixes.get(top, 0) + 1
for k, v in sorted(prefixes.items(), key=lambda kv: -kv[1]):
    print(f"    {k:24s} {v}")

print()
print("=== 5. python files parse ===")
bad = []
checked = 0
for rev in (ORIG, INTEG):
    for path in tree(rev):
        if not path.endswith(".py"):
            continue
        src = subprocess.run(
            ["git", "show", f"{rev}:{path}"], capture_output=True
        ).stdout
        checked += 1
        try:
            compile(src, path, "exec")
        except SyntaxError as e:
            bad.append(f"{rev}:{path}: {e}")
print(f"  python files compiled: {checked}")
print(f"  syntax errors: {len(bad)}")
for b in bad[:10]:
    print(f"    {b}")

sys.exit(0 if not missing and not bad else 1)