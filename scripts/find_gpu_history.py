"""Search Firefox browsing history for GPU-hour signup pages.

Firefox keeps history in places.sqlite (moz_places). We copy it out of the profile
first, because the live DB is locked while Firefox runs. Read-only: nothing is
written back to the profile, and the copy is removed at the end.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

APPDATA = Path(os.environ["APPDATA"])
PROFILES = APPDATA / "Mozilla/Firefox/Profiles"

# A page that grants GPU hours would match one of these.
NEEDLES = [
    "gpu", "compute-hour", "compute_credit", "credits", "colab",
    "lightning.ai", "runpod", "vast.ai", "lambda", "paperspace",
    "modal.com", "kaggle.com/code", "deepnote", "weights", "wandb",
    "hackathon", "find-evil", "sans.org", "huggingface.co/spaces",
    "tensordock", "massedcompute", "hyperstack", "coreweave",
]

# Hosts that indicate a GPU/compute provider specifically.
PROVIDERS = [
    "lightning.ai", "colab.research.google", "kaggle.com", "runpod.io",
    "vast.ai", "lambdalabs", "paperspace", "modal.com", "deepnote.com",
    "tensordock", "jarvislabs", "massedcompute", "hyperstack", "coreweave",
    "genesiscloud", "fluidstack", "nvidia.com", "aws.amazon.com/sagemaker",
]


def search(profile: Path) -> None:
    db = profile / "places.sqlite"
    if not db.is_file():
        return
    tmp = Path(tempfile.gettempdir()) / f"places_{profile.name}.sqlite"
    try:
        shutil.copy2(db, tmp)
    except OSError as e:
        print(f"  {profile.name}: copy failed ({e})")
        return

    print(f"=== {profile.name}  ({db.stat().st_size / 1_048_576:.0f} MB)")
    try:
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        cur = con.cursor()

        # Hosts whose visits look like a compute provider.
        where = " OR ".join(["url LIKE ?"] * len(NEEDLES))
        params = [f"%{n}%" for n in NEEDLES]
        cur.execute(
            f"""SELECT url, title, visit_count, datetime(last_visit_date/1000000,'unixepoch')
                FROM moz_places
                WHERE ({where}) AND url NOT LIKE '%google.com/search%'
                ORDER BY last_visit_date DESC LIMIT 60""",
            params,
        )
        rows = cur.fetchall()
        seen = set()
        shown = 0
        for url, title, vc, last in rows:
            host = url.split("/")[2] if "://" in url else url
            key = (host, url.split("?")[0][:90])
            if key in seen:
                continue
            seen.add(key)
            is_provider = any(p in url.lower() for p in PROVIDERS)
            tag = "  <== PROVIDER" if is_provider else ""
            print(f"  [{vc:>3}x] {str(last)[:16]}  {host}{tag}")
            print(f"         {(title or '')[:88]}")
            print(f"         {url[:150]}")
            shown += 1
            if shown >= 35:
                break
        if not shown:
            print("  no GPU/compute/hackathon history in this profile")

        # Provider login URLs specifically, which is the strongest signal.
        cur.execute(
            """SELECT DISTINCT url, visit_count FROM moz_places
               WHERE (url LIKE '%login%' OR url LIKE '%signup%' OR url LIKE '%/sign-up%'
                      OR url LIKE '%/dashboard%')
                 AND (url LIKE '%lightning%' OR url LIKE '%runpod%' OR url LIKE '%vast.ai%'
                      OR url LIKE '%colab%' OR url LIKE '%kaggle%' OR url LIKE '%lambda%'
                      OR url LIKE '%modal.com%' OR url LIKE '%paperspace%'
                      OR url LIKE '%tensordock%' OR url LIKE '%jarvislabs%')
               ORDER BY visit_count DESC LIMIT 15"""
        )
        auth = cur.fetchall()
        if auth:
            print("  -- auth/dashboard pages (strongest signal) --")
            for url, vc in auth:
                print(f"    [{vc:>3}x] {url[:140]}")
        con.close()
    except sqlite3.Error as e:
        print(f"  sqlite error: {e}")
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


for p in sorted(PROFILES.glob("*.default*")):
    if p.is_dir():
        search(p)
for p in sorted(PROFILES.iterdir()):
    if p.is_dir() and "default" not in p.name:
        search(p)