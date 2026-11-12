"""List secret-role files and the KEY NAMES they define, never the values.

Key names are safe to read: they say which credentials exist, not what they are.
This exists so a task can discover whether a credential is already set up without
anyone printing or pasting a secret.
"""
from pathlib import Path

ROLES = Path(r"C:\Users\Owner\.secret-roles")

for p in sorted(ROLES.glob("*.env")):
    keys = []
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        continue
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            keys.append(s.split("=", 1)[0].strip())
    if keys:
        print(p.name + ": " + ", ".join(keys))