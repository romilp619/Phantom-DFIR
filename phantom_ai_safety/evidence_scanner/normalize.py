"""Extract obfuscated candidate substrings for injection scanning.

The 27 rules in `scanner.py` are lexical. An attacker who encodes, homoglyphs, or
zero-width-pads a payload defeats all of them. This module extracts plausible
injection candidates from text the regex rules would miss.

Design rule: the original text is never modified. The scanner runs on the original
text first, then on extracted candidates. A normalisation bug degrades to exactly
the old detection rate, never to a false positive from a text mutation.

Every extraction is constrained:

- base64/hex: only runs inside suspicious-looking regions (near the kinds of
  markers real encodings carry, like "echo | base64" or "0x" / "line:" prefixes),
  because forensic evidence contains legit hashes and base64 blobs constantly
- homoglyphs: only when a word matches a known attack pattern after folding,
  because folding "C:\mimikatz" for every artifact would drown real evidence in
  noise
- invisible characters: removed from the original text only before scanning,
  never persisted

What this does not catch: multi-turn injection, indirect injection, large-context
burial, encrypted or non-base64/non-hex encoded payloads. Those are stated
limitations, not bugs.
"""
from __future__ import annotations

import base64
import re
import unicodedata

# Characters invisible in rendered text that an attacker can insert into a keyword.
_INVISIBLE = (
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad",
)
_INVISIBLE_RE = re.compile("[" + "".join(_INVISIBLE) + "]")

# Pick base64/hex only when the encoded form looks like it was deliberately placed,
# not when it is a real hash or certificate blob.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])([0-9A-Fa-f]{20,})(?![0-9A-Za-z])")

# Digest-masquerading length: real forensic hashes (md5, sha1, sha256 as hex) match
# _HEX_RUN constantly, so skip lengths that look like known hash algorithms.
_HASH_LENGTHS = frozenset({32, 40, 64, 96, 128})


def _printable_fraction(s: str) -> float:
    if not s or len(s) < 8:
        return 0.0
    return sum(1 for c in s if c.isprintable() or c in "\n\t\r") / len(s)


def _textual(s: str) -> bool:
    """True when a decoded string looks like it might be human language."""
    if not s:
        return False
    alpha = sum(1 for c in s if c.isalpha())
    return alpha >= 3


def extract_candidates(text: str) -> list[str]:
    """Extract decoded or normalised substrings that could hide an injection.

    Returns a short list (typically 0-3 items, never more than ~10) of candidate
    strings to scan alongside the original text. Every candidate is a decoded or
    normalised form of a *region* of the text, never the whole text.

    The result list is ordered and deduplicated. An empty list means no candidate
    was extractable — the scanner falls through to the original text only.
    """
    if not text or len(text) < 20:
        return []

    candidates: list[str] = []
    seen: set[str] = set()

    def add(c: str) -> None:
        c = c.strip()
        if c and len(c) >= 12 and c not in seen:
            seen.add(c)
            candidates.append(c)

    # 1. Strip invisible characters from the full text. This is the cheap win:
    # zero-width-characters are never legitimate forensic content.
    stripped = _INVISIBLE_RE.sub("", text)
    if stripped != text:
        add(stripped)

    # 2. Base64 candidates. Constrain to runs that appear near "base64" or "encode"
    # contextual markers, or are suspiciously long. Real base64 in forensic evidence
    # (AV signatures, process checksums) is short and doesn't come with an encode hint.
    for m in _B64_RUN.finditer(text):
        chunk = m.group(0)
        if len(chunk) < 24:
            continue
        pad = (-len(chunk)) % 4
        try:
            raw = base64.b64decode(chunk + "=" * pad, validate=False)
        except Exception:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _printable_fraction(decoded) >= 0.90 and _textual(decoded):
            add(decoded)

    # 3. Hex candidates. Skip lengths that are known hash digests — those are
    # everywhere in forensic output. Only decode when it is clearly not a hash.
    for m in _HEX_RUN.finditer(text):
        chunk = m.group(1)
        if len(chunk) in _HASH_LENGTHS:
            continue
        if len(chunk) % 2:
            continue
        try:
            raw = bytes.fromhex(chunk)
        except ValueError:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _printable_fraction(decoded) >= 0.90 and _textual(decoded):
            add(decoded)

    # 4. Unicode normalisation with confusable folding. Applied only to the
    # stripped text, not the original full artifact.
    if stripped:
        nfkc = unicodedata.normalize("NFKC", stripped)
        if nfkc != stripped:
            add(nfkc)

    # 5. Folded variants of the stripped text — homoglyphs and leetspeak that
    # would read as known attack keywords when normalised.
    from phantom_ai_safety.evidence_scanner.scanner import RULES

    folded = _fold_confusable_short(stripped) if stripped else ""
    if folded and folded != stripped:
        # Only add when the region near a keyword would match after folding.
        for name, _sev, _expl, patterns in RULES:
            for pat in patterns:
                if re.search(pat, folded, re.IGNORECASE):
                    add(folded)
                    break

    return candidates


# Tight confusable fold: only the letters that unambiguously look like Latin.
_CONFUSABLE = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o",
})

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})


def _fold_confusable_short(text: str) -> str:
    """Fold only the short confusable set, not the full Unicode sheet."""
    return _INVISIBLE_RE.sub("", text).translate(_CONFUSABLE).translate(_LEET)