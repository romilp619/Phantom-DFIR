"""Check the WORKING TREE against the integrated commit, file by file.

My earlier audit compared commits to commits. That answers "is the merge correct in
git" but not "is the merge actually on disk". A checkout that was interrupted, or a
branch that was never switched, leaves the two different - and only the working tree
is what a person runs.

Read-only.
"""
from __future__ import annotations

import subprocess
import sys

INTEG = "2fa27b6"
ORIG = "3005762"


def run(*a: str) -> str:
    return subprocess.run(list(a), capture_output=True, text=True).stdout


def tree(rev: str) -> set[str]:
    out = run("git", "ls-tree", "-r", rev, "--name-only")
    return {p for p in out.splitlines() if p.strip()}


integ_files = tree(INTEG)
orig_files = tree(ORIG)

# What git thinks is in the index (the checkout's intent).
indexed = set(run("git", "ls-files").splitlines())
indexed = {p for p in indexed if p.strip()}

print(f"original  {ORIG}: {len(orig_files)} files")
print(f"integrated {INTEG}: {len(integ_files)} files")
print(f"index now         : {len(indexed)} files")
print()

missing_from_index = sorted(integ_files - indexed)
extra_in_index = sorted(indexed - integ_files)

print("=== files in the integrated commit but NOT in the current index ===")
if missing_from_index:
    for p in missing_from_index:
        print(f"  {p}")
else:
    print("  none - the index matches the integration commit")

print()
print("=== files in the index but not in the integrated commit ===")
for p in extra_in_index:
    print(f"  {p}")

# The decisive test: is each original engine file present on disk?
print()
print("=== the 86 originals: present on disk? ===")
absent = []
present = 0
for p in sorted(orig_files):
    try:
        subprocess.run(["git", "ls-files", "--error-unmatch", p], capture_output=True, check=True)
        present += 1
    except subprocess.CalledProcessError:
        absent.append(p)

print(f"  tracked in index : {present} of {len(orig_files)}")
if absent:
    print(f"  NOT tracked      : {len(absent)}")
    for p in absent:
        print(f"      {p}")
else:
    print("  all original files are tracked")

print()
# Engine modules specifically - these are the ones that must exist to run.
ENGINE_DIRS = ("agents/", "tools/", "correlation/", "state/", "config/",
               "reporting/", "packaging/")
print("=== engine package files: on disk? ===")
engine_gap = []
for p in sorted(orig_files):
    if not p.startswith(ENGINE_DIRS):
        continue
    if p not in indexed:
        engine_gap.append(p)
    elif not __import__("pathlib").Path(p).exists():
        engine_gap.append(p + "  (tracked but MISSING FROM DISK)")
if engine_gap:
    for p in engine_gap:
        print(f"  {p}")
else:
    print("  every engine file is present")