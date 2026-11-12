"""Emit the authoritative classification of the original tree, from git.

The first version of the audit report listed filenames that do not exist in either tree.
This script exists so the classification is GENERATED from the repository rather than
recalled, and so the mistake cannot recur.

Read-only. Prints markdown.
"""
from __future__ import annotations

import collections
import subprocess

ORIG = "3005762"
INTEG = "2fa27b6"


def tree(rev: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", rev, "--name-only"], capture_output=True, text=True
    ).stdout
    return [p for p in out.splitlines() if p.strip()]


def real(rev: str) -> list[str]:
    """Exclude __pycache__: compiled bytecode is not source and would inflate counts."""
    return [p for p in tree(rev) if "__pycache__" not in p]


orig, integ = real(ORIG), real(INTEG)
missing = sorted(set(orig) - set(integ))
additive = sorted(set(integ) - set(orig))
common = sorted(set(orig) & set(integ))

print(f"ORIGINAL {ORIG}: {len(orig)} files ({len(tree(ORIG))} including __pycache__)")
print(f"INTEGRATED {INTEG}: {len(integ)} files ({len(tree(INTEG))} including __pycache__)")
print()
print(f"common paths      : {len(common)}")
print(f"original missing  : {len(missing)}")
print(f"additive paths    : {len(additive)}")
print()

# Classify the shared originals by what they are.
CATEGORIES = [
    ("Engine sources - Python that runs", lambda p: p.endswith(".py")),
    ("Static reference data", lambda p: p.endswith(".json") and not p.endswith(".py")),
    ("Run logs (evidence of real runs)", lambda p: p.startswith("logs/")),
    ("Skills (agent playbooks)", lambda p: p.startswith("skills/")),
    ("Docs and prose", lambda p: p.endswith(".md")),
    ("Install / packaging", lambda p: p in {"install.sh", ".gitattributes"}),
    ("Binary assets", lambda p: p.endswith((".png", ".img"))),
]

assigned: set[str] = set()
print("=== SHARED ORIGINAL FILES, by category ===")
for name, pred in CATEGORIES:
    hits = sorted(p for p in common if pred(p) and p not in assigned)
    assigned.update(hits)
    if hits:
        print(f"\n**{name} - {len(hits)}**")
        for h in hits:
            print(f"- `{h}`")

leftover = sorted(set(common) - assigned)
if leftover:
    print(f"\n**Unclassified - {len(leftover)}**")
    for h in leftover:
        print(f"- `{h}`")

print()
print(f"category total: {len(assigned)} (+ {len(leftover)} unclassified) = {len(common)}")

print()
print("=== ADDITIVE PATHS (the AI module), by top-level dir ===")
counts = collections.Counter(p.split("/")[0] if "/" in p else "(root)" for p in additive)
for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
    print(f"- `{k}/` - {v}")

print()
print("=== ORIGINAL FILES ABSENT FROM THE INTEGRATION ===")
if missing:
    for m in missing:
        print(f"- `{m}`")
else:
    print("NONE. Every one of the {0} original files survives.".format(len(orig)))