"""Search the Proton mailbox through the local Bridge for GPU-hour signup mail.

Reads credentials from the secret-role env file and talks IMAP to Bridge on
localhost. Prints sender/subject/date only - never message bodies, never the
password. Exits 0 whether or not anything matches.
"""
from __future__ import annotations

import email
import imaplib
import os
import re
import sys
from email.header import decode_header
from pathlib import Path

ROLE = Path(r"C:\Users\Owner\.secret-roles\vault-readcheck.env")


def load_role(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, v = s.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def dec(raw) -> str:
    if not raw:
        return ""
    out = []
    for part, enc in decode_header(raw):
        if isinstance(part, bytes):
            try:
                out.append(part.decode(enc or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                out.append(part.decode("utf-8", errors="replace"))
        else:
            out.append(part)
    return " ".join(out)


# What a GPU-hour signup confirmation would look like.
PATTERNS = [
    r"gpu", r"compute\s*(hours|credit)", r"colab", r"lightning\.ai",
    r"kaggle", r"runpod", r"vast\.ai", r"lambda\s*labs", r"paperspace",
    r"modal", r"replicate", r"deepnote", r"weights\s*&?\s*biases",
    r"credit", r"hackathon",
]
TERMS = re.compile("|".join(PATTERNS), re.IGNORECASE)

# The account itself is not a signup target.
NOISE = re.compile(r"newsletter|digest|receipt|invoice|shipped|order confirm", re.IGNORECASE)


def main() -> int:
    env = load_role(ROLE)
    user = env.get("PROTON_USER") or env.get("IMAP_USER") or env.get("PROTON_EMAIL")
    pw = env.get("PROTON_PASS") or env.get("IMAP_PASS") or env.get("PROTON_PASSWORD")
    host = env.get("IMAP_HOST", "127.0.0.1")
    port = int(env.get("IMAP_PORT", "1143"))

    if not user or not pw:
        # Fall back to the role whose name suggests mail, if the keys differ.
        print(f"no proton credentials found in {ROLE.name}")
        print("keys present: " + ", ".join(sorted(env)) if env else "file empty or missing")
        return 0

    print(f"connecting {host}:{port} as {user}")
    try:
        M = imaplib.IMAP4(host, port)
        M.starttls()
    except Exception:
        M = imaplib.IMAP4(host, port)
    M.login(user, pw)
    M.select("INBOX")

    typ, data = M.search(None, "ALL")
    ids = data[0].split()
    print(f"inbox messages: {len(ids)}")

    hits = []
    # Newest first, bounded so a large inbox does not take forever.
    for mid in reversed(ids[-2000:]):
        try:
            typ, msgdata = M.fetch(mid, "(RFC822.HEADER)")
            if typ != "OK" or not msgdata or not msgdata[0]:
                continue
            msg = email.message_from_bytes(msgdata[0][1])
        except Exception:
            continue
        subj = dec(msg.get("Subject"))
        frm = dec(msg.get("From"))
        date = msg.get("Date", "")
        if NOISE.search(subj):
            continue
        if TERMS.search(subj) or TERMS.search(frm):
            hits.append((date, frm, subj))

    M.logout()

    if not hits:
        print("no GPU/compute signup mail matched")
        return 0

    print(f"\nmatches: {len(hits)}")
    for date, frm, subj in hits[:40]:
        print(f"  {date[:31]:<31} | {frm[:44]:<44} | {subj[:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())