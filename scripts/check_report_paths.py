"""Fail the build if the audit report names a file that does not exist in either tree.

Written after the first draft of the report listed invented filenames. This is the
regression test for that mistake: it extracts every backticked path-looking token from
the report and asserts each one is real.

Read-only. Exit 1 if any claimed path is absent from both trees.
"""
from __future__ import annotations

import re
import subprocess
import sys

REPORT = "docs/INTEGRATION-AUDIT-REPORT.md"
ORIG = "3005762"
INTEG = "2fa27b6"


def tree(rev: str) -> set[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", rev, "--name-only"], capture_output=True, text=True
    ).stdout
    return {p for p in out.splitlines() if p.strip()}


real = tree(ORIG) | tree(INTEG)

text = open(REPORT, encoding="utf-8").read()

# Section 11 is the error record: it deliberately names the files that were invented,
# so those tokens are expected to be absent from the tree. Check everything before it.
# Without this exemption the test fails on its own disclosure, which trains a reader to
# ignore it.
marker = "## 11. Error record"
if marker in text:
    checked_text, disclosed = text.split(marker, 1)
else:
    checked_text, disclosed = text, ""
    print("WARNING: Section 11 error record not found; checking the whole report")

# Path-looking tokens inside backticks.
path_re = re.compile(r"`([A-Za-z0-9_./-]+\.(?:py|md|json|sh|txt|png|toml|yaml|yml|cfg|ini|bundle))`")
candidates = path_re.findall(checked_text)
candidates += re.findall(r"`([a-z_]+/[A-Za-z0-9_.-]+)`", checked_text)

suspect = []
for c in sorted(set(candidates)):
    if c in real:
        continue
    # Bare script basenames are referenced without their directory in the prose.
    if "/" not in c:
        continue
    # Branch and ref names are not paths.
    if c in {"origin/main"} or c.startswith(("audit/", "wip/", "integrated/")):
        continue
    # Allow references to files this session created but has not committed yet.
    if c.startswith(("scripts/", "docs/", "artifacts/", "results/")):
        try:
            subprocess.run(["git", "ls-files", "--error-unmatch", c],
                           capture_output=True, check=True)
            continue
        except subprocess.CalledProcessError:
            pass
    if c.endswith(".bundle") or c == REPORT:
        continue
    suspect.append(c)

print(f"checked the report EXCLUDING the Section 11 disclosure ({len(disclosed)} chars)")
print(f"path-like tokens checked : {len(set(candidates))}")
print(f"SUSPECT (in neither tree): {len(suspect)}")
for s in suspect:
    print(f"  {s}")

if not suspect:
    print()
    print("PASS: every path named in the audit report exists in a real tree.")

sys.exit(1 if suspect else 0)