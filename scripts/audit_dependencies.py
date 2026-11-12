"""Find every third-party import in the integrated tree that requirements.txt does not pin.

This is the dependency audit the report needs: what the code imports vs what the
installer declares. Read-only; nothing is modified.

Method: parse each .py / .sh in the integrated tree, collect top-level module names
from `import X` and `from X import`, subtract the standard library (via
sys.stdlib_module_names), subtract first-party packages, then compare against the
pinned names in requirements.txt.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys

INTEG = "2fa27b6"

# First-party packages in this repo (present as directories, not installed).
FIRST_PARTY = {
    "phantom_ai_safety", "agents", "config", "correlation", "state", "tools",
    "dashboard", "scripts", "tests", "artifacts", "data", "docs", "results",
    "reporting", "packaging", "integrations", "core", "analysis",
}

# Import name -> PyPI distribution name, where they differ.
DIST_NAME = {
    "yaml": "PyYAML", "cv2": "opencv-python", "PIL": "Pillow",
    "sklearn": "scikit-learn", "bs4": "beautifulsoup4", "dotenv": "python-dotenv",
    "fitz": "PyMuPDF", "dateutil": "python-dateutil", "jwt": "PyJWT",
    "OpenSSL": "pyOpenSSL", "serial": "pyserial", "usb": "pyusb",
    "Crypto": "pycryptodome", "StringIO": "?stdlib?", "redis": "redis",
    "pydantic_settings": "pydantic-settings", "multipart": "python-multipart",
    "google": "google-api-python-client", "huggingface_hub": "huggingface-hub",
    "transformers": "transformers", "peft": "peft", "datasets": "datasets",
    "sentencepiece": "sentencepiece", "accelerate": "accelerate",
}

# Import name -> package it provides but is NOT pip-installable this way.
KNOWN_OPTIONAL = {"volatility", "vol", "volatility3"}


def tree_files(rev: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-tree", "-r", rev, "--name-only"], capture_output=True, text=True
    ).stdout
    return [p for p in out.splitlines() if p.strip()]


def top_level_imports(src: bytes) -> set[str]:
    """Top-level module names imported by a python source blob."""
    names: set[str] = set()
    try:
        node = ast.parse(src)
    except (SyntaxError, ValueError):
        # Fall back to regex for files ast cannot parse (e.g. BOM issues).
        text = src.decode("utf-8", errors="replace")
        for m in re.finditer(r"^\s*import\s+([\w.]+)", text, re.M):
            names.add(m.group(1).split(".")[0])
        for m in re.finditer(r"^\s*from\s+([\w.]+)\s+import", text, re.M):
            names.add(m.group(1).split(".")[0])
        return names

    for n in ast.walk(node):
        if isinstance(n, ast.Import):
            for a in n.names:
                names.add(a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            if n.level == 0 and n.module:
                names.add(n.module.split(".")[0])
    return names


files = tree_files(INTEG)
py_files = [f for f in files if f.endswith(".py")]

found: dict[str, list[str]] = {}
for path in py_files:
    src = subprocess.run(
        ["git", "show", f"{INTEG}:{path}"], capture_output=True
    ).stdout
    for name in top_level_imports(src):
        found.setdefault(name, []).append(path)

stdlib = set(sys.stdlib_module_names)
third_party = {
    k: v for k, v in found.items()
    if k not in stdlib and k not in FIRST_PARTY and not k.startswith("_")
}

req = subprocess.run(
    ["git", "show", f"{INTEG}:requirements.txt"], capture_output=True, text=True
).stdout
pinned = set()
for line in req.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    name = re.split(r"[<>=!~\[]", line)[0].strip().lower()
    if name:
        pinned.add(name)

print(f"python files scanned : {len(py_files)}")
print(f"third-party imports  : {len(third_party)}")
print(f"pinned in reqs.txt   : {len(pinned)}")
print()

missing = {}
for name, users in sorted(third_party.items()):
    dist = DIST_NAME.get(name, name)
    if name.lower() in pinned or dist.lower() in pinned:
        continue
    if name in KNOWN_OPTIONAL:
        continue
    missing[name] = (dist, users)

print(f"=== MISSING from requirements.txt: {len(missing)} ===")
for name, (dist, users) in missing.items():
    print(f"  {name:22s} -> {dist:26s} used by {len(users)} file(s)")
    for u in users[:3]:
        print(f"        {u}")
    if len(users) > 3:
        print(f"        ... and {len(users) - 3} more")

print()
print("=== present but worth confirming ===")
for name in sorted(third_party):
    dist = DIST_NAME.get(name, name)
    if name.lower() in pinned or dist.lower() in pinned:
        print(f"  {name:22s} pinned OK")