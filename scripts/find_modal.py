"""Full Modal + hackathon browsing history, with visit counts and dates."""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

PROFILES = [
    Path(os.environ["APPDATA"]) / "Mozilla/Firefox/Profiles/7fy5qstw.default-release",
]

QUERY = """
SELECT url, title, visit_count,
       datetime(last_visit_date/1000000,'unixepoch') AS last
FROM moz_places
WHERE (url LIKE '%modal%' OR url LIKE '%lexsi%' OR url LIKE '%hackathon%'
       OR url LIKE '%lightning%' OR url LIKE '%runpod%' OR url LIKE '%kaggle%'
       OR url LIKE '%colab%' OR url LIKE '%vast.ai%' OR url LIKE '%lambda%')
ORDER BY last_visit_date DESC
LIMIT 60
"""

for prof in PROFILES:
    db = prof / "places.sqlite"
    if not db.is_file():
        continue
    tmp = Path(tempfile.gettempdir()) / "hx_scan.sqlite"
    shutil.copy2(db, tmp)
    print(f"=== {prof.name}")
    try:
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        for url, title, vc, last in con.execute(QUERY):
            print(f"  [{vc}x] {str(last)[:16]}  {(title or '')[:72]}")
            print(f"        {url[:135]}")
        con.close()
    except sqlite3.Error as e:
        print(f"  error: {e}")
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass