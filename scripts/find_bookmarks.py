"""Dump Chrome bookmarks, highlighting social/X links.

Chrome stores bookmarks as nested JSON under roots.<bar>.<children>. A recursive
walk is needed; the roots object itself is a container, not a bar.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

CANDIDATES = [
    Path(os.environ["LOCALAPPDATA"]) / "Google/Chrome/User Data/Default/Bookmarks",
    Path(os.environ["LOCALAPPDATA"]) / "Google/Chrome/User Data/Profile 1/Bookmarks",
    Path(os.environ["LOCALAPPDATA"]) / "Google/Chrome/User Data/Profile 2/Bookmarks",
]

SOCIAL = ("x.com", "twitter.com", "nitter.")
KEY = ("gpu", "compute", "credit", "colab", "lightning", "runpod", "kaggle",
       "vast", "lambda", "paperspace", "modal", "hackathon", "find evil")


def walk(node, depth=0, out=None):
    if out is None:
        out = []
    if isinstance(node, dict):
        if node.get("type") == "url":
            out.append((depth, node.get("name", ""), node.get("url", "")))
        for c in node.get("children", []) or []:
            walk(c, depth + 1, out)
    return out


found_any = False
for path in CANDIDATES:
    if not path.is_file():
        continue
    found_any = True
    print(f"=== {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        print(f"  parse failed: {e}")
        continue
    roots = data.get("roots", {})
    entries = []
    for bar_name, bar in roots.items():
        if isinstance(bar, dict):
            sub = walk(bar, 0, [])
            for d, name, url in sub:
                entries.append((bar_name, d, name, url))
    print(f"  bookmarks: {len(entries)}")
    for bar_name, d, name, url in entries:
        low = (name + " " + url).lower()
        is_social = any(s in low for s in SOCIAL)
        is_key = any(k in low for k in KEY)
        tag = ""
        if is_social:
            tag += "  [SOCIAL]"
        if is_key:
            tag += "  [GPU-KEYWORD]"
        if tag:
            print(f"  {bar_name}/{('  ' * d)}{name}{tag}")
            print(f"        {url}")
    if not any(any(s in (n + " " + u).lower() for s in SOCIAL) for _, _, n, u in entries):
        print("  (no x.com/twitter bookmarks in this profile)")

if not found_any:
    print("no Chrome bookmark files found")