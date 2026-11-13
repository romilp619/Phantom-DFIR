"""Categorise each unpinned import by whether it is REQUIRED at import time or LAZY.

A dependency needed only inside a function body is optional at startup: the process
boots and the feature fails when used. A dependency needed at module import time kills
the process on start. The two need different treatment in an installer, so the audit
must distinguish them rather than lumping both as "missing".

Read-only.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys

INTEG = "2fa27b6"
UNPINNED = [
    "Evtx", "aligntune", "curatorkit", "langchain_anthropic", "langchain_core",
    "langchain_groq", "langchain_ollama", "langchain_openai", "matplotlib",
    "numpy", "peft", "pytest", "torch", "transformers", "trl",
]
FIRST_PARTY = {
    "phantom_ai_safety", "agents", "config", "correlation", "state", "tools",
    "dashboard", "scripts", "tests",
}


def files(rev: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", rev, "--name-only"], capture_output=True, text=True
    ).stdout
    return [p for p in out.splitlines() if p.endswith(".py")]


def classify(src: bytes, target: str) -> tuple[bool, bool]:
    """Return (used_at_module_level, used_inside_function)."""
    try:
        root = ast.parse(src)
    except (SyntaxError, ValueError):
        return (False, False)

    top = False
    lazy = False

    for node in ast.walk(root):
        hit = False
        if isinstance(node, ast.Import):
            hit = any(a.name.split(".")[0] == target for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            hit = node.level == 0 and bool(node.module) and node.module.split(".")[0] == target
        if not hit:
            continue
        # Determine nesting depth by walking children of module-level statements.
        if any(node is child for stmt in root.body for child in ast.walk(stmt)
               if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Try, ast.If))):
            pass
        if node in ast.walk(root):
            # module-level = the import node is reachable without entering a FunctionDef
            def in_function(n, tree):
                for fn in ast.walk(tree):
                    if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if any(c is n for c in ast.walk(fn)):
                            return True
                return False
            if in_function(node, root):
                lazy = True
            else:
                top = True

    return (top, lazy)


rows = []
for path in files(INTEG):
    src = subprocess.run(["git", "show", f"{INTEG}:{path}"], capture_output=True).stdout
    for dep in UNPINNED:
        top, lazy = classify(src, dep)
        if top or lazy:
            rows.append((dep, path, top, lazy))

by_dep: dict[str, dict] = {}
for dep, path, top, lazy in rows:
    e = by_dep.setdefault(dep, {"top": [], "lazy": [], "first_party": dep in FIRST_PARTY})
    if top:
        e["top"].append(path)
    if lazy:
        e["lazy"].append(path)

print(f"{'dependency':22s} {'first-party':12s} {'import-time':12s} {'lazy':6s}")
print("-" * 60)
for dep in UNPINNED:
    e = by_dep.get(dep)
    if not e:
        continue
    fp = "yes" if e["first_party"] else "no"
    top_n = len(e["top"])
    lazy_n = len(e["lazy"])
    verdict = "REQUIRED" if top_n else "optional"
    print(f"{dep:22s} {fp:12s} {top_n:>4} {verdict:10s} {lazy_n:>4}")

print()
print("=== REQUIRED at import time (must be installed or the process will not start) ===")
for dep, e in sorted(by_dep.items()):
    if e["top"] and not e["first_party"]:
        print(f"  {dep}")
        for p in e["top"][:3]:
            print(f"      {p}")

print()
print("=== LAZY only (feature degrades, process still boots) ===")
for dep, e in sorted(by_dep.items()):
    if not e["top"] and not e["first_party"]:
        print(f"  {dep:22s} {len(e['lazy'])} file(s)")

print()
print("=== FIRST-PARTY-looking (ship with the repo, not pip) ===")
for dep, e in sorted(by_dep.items()):
    if e["first_party"]:
        print(f"  {dep:22s} top={len(e['top'])} lazy={len(e['lazy'])}")