"""Adversarial probe of the normalisation pass, hunting for false positives and cost.

The normalisation pass is the newest code and the one most likely to create a false
positive, because it manufactures text that was not in the artifact. This script
throws real forensic noise at it and reports anything that gets flagged, plus the
cost of running normalisation on realistic artifacts.

Run:  python scripts/probe_normalize.py
"""
from __future__ import annotations

import secrets
import string
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phantom_ai_safety.evidence_scanner import normalize, scanner  # noqa: E402

# Realistic forensic artifacts that must never be flagged.
BENIGN = (
    ("volatility pslist",
     "Offset(P) Name PID PPID Thds Hnds Time\n"
     "0x00000000 svchost.exe 882 612 24 421 2026-11-11 22:14:02"),
    ("volatility malfind",
     "Process: explorer.exe Pid: 4412 Address: 0x1f0000\n"
     "Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE\n"
     "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00"),
    ("sha256 hashes",
     "sha256 a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447\n"
     "sha256 b7c9f1e1a5b3e8c2d4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0"),
    ("md5 and sha1",
     "md5 d41d8cd98f00b204e9800998ecf8427e\n"
     "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ("windows event log",
     "EventID 4624 Logon Type 3 Account DOMAIN\\user Source 10.0.0.5 Time 22:15:01"),
    ("registry key",
     "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater = C:\\Temp\\upd.exe"),
    ("prefetch",
     "MFT entry 44201: \\Windows\\Prefetch\\CMD.EXE-89305D47.pf run 14 times"),
    ("network connections",
     "10.0.0.5:49712 -> 93.184.216.34:443 ESTABLISHED pid 4412 chrome.exe"),
    ("base64 cert blob",
     "-----BEGIN CERTIFICATE-----\n"
     "MIIEpAIBAAKCAQEAwZx+T4x7Q4tFGaN0o0asd+NVI3Xf+6B0m9JGEuCAD0Cq\n"
     "-----END CERTIFICATE-----"),
    ("base64 image data",
     "thumbnail iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="),
    ("hex registry blob",
     "value raw 01000000a8000000b4010000c8000000"),
    ("powershell encodedcommand with benign payload",
     "powershell -enc R2V0LUNoaWxkSXRlbSAtUGF0aCBDOlxcVGVtcA=="),
    ("user comment about analysis",
     "The analyst should review the DLL injection before concluding the host is infected."),
    ("path with confusable-looking but ascii",
     "C:\\Users\\Public\\Downloads\\invoice_final_v2.pdf"),
    ("long evidence line",
     "commandline: \"C:\\Program Files\\Common Files\\svchost.exe\" -k netsvcs -p -s Schedule"),
    ("unicode hostname",
     "hostname: m\u00fcnchen-srv01.example.com resolved to 10.0.0.11"),
    ("cyrillic text legitimately present",
     "\u041e\u0442\u0447\u0451\u0442 \u043e \u0441\u0438\u0441\u0442\u0435\u043c\u0435 \u0431\u044b\u043b \u0441\u043e\u0437\u0434\u0430\u043d 2026-11-11"),
)


def main() -> int:
    print("=== false-positive probe: benign forensic artifacts ===")
    flagged = []
    for label, text in BENIGN:
        r = scanner.scan_artifact(label, text)
        if r.findings:
            flagged.append((label, [(f.category, f.severity, f.matched_text[:50]) for f in r.findings]))
            print(f"  FLAGGED  {label}")
            for cat, sev, mt in flagged[-1][1]:
                print(f"           {cat} ({sev}): {mt!r}")
        else:
            print(f"  clean    {label}")
    print()
    print(f"  {len(flagged)} of {len(BENIGN)} benign artifacts flagged")
    print()

    # Random high-entropy strings: base64 alphabet, hash-like, should all be rejected.
    print("=== false-positive probe: random high-entropy strings ===")
    alphabet = string.ascii_letters + string.digits + "+/"
    b64_fp = 0
    for _ in range(200):
        blob = "".join(secrets.choice(alphabet) for _ in range(64))
        cands = normalize.extract_candidates(f"blob: {blob}")
        if cands:
            b64_fp += 1
    print(f"  200 random base64 blobs -> {b64_fp} produced candidates")
    hex_fp = 0
    for _ in range(200):
        blob = "".join(secrets.choice("0123456789abcdef") for _ in range(48))
        cands = normalize.extract_candidates(f"value: {blob}")
        if cands:
            hex_fp += 1
    print(f"  200 random hex blobs (48 chars) -> {hex_fp} produced candidates")
    print()

    # Cost on realistic long artifacts.
    print("=== cost of normalisation ===")
    long_text = "\n".join(t for _, t in BENIGN) * 20
    print(f"  synthetic artifact: {len(long_text):,} chars")
    t0 = time.perf_counter()
    for _ in range(5):
        normalize.extract_candidates(long_text)
    extract_ms = (time.perf_counter() - t0) * 1000 / 5
    print(f"  extract_candidates: {extract_ms:.2f} ms")
    t0 = time.perf_counter()
    for _ in range(5):
        scanner.scan_artifact("x", long_text)
    scan_ms = (time.perf_counter() - t0) * 1000 / 5
    print(f"  full scan (raw + normalise): {scan_ms:.2f} ms")
    print(f"  normalisation share: {100*extract_ms/scan_ms:.0f}%")
    print()

    return 0 if not flagged and b64_fp == 0 and hex_fp == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())