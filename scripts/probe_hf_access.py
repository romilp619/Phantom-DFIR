"""Probe Hugging Face gating status for candidate Cohere backbones.

The track expects a sponsor open-weights model. The Tiny Aya family is gated, which blocks
an unattended run. This script asks the HF API for each candidate's gating status
anonymously, so the blocker is established by evidence rather than assumed.

Gating values returned by the API:
  false   -> downloads work anonymously
  "auto"  -> the account must accept terms once, then a token works
  "manual"-> a human at the org must approve access

Exit codes: 0 if at least one candidate is usable anonymously, 2 if all are gated.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

CANDIDATES = [
    # The recommended model family.
    "CohereLabs/tiny-aya-global",
    "CohereLabs/tiny-aya-base",
    "CohereLabs/tiny-aya-fire",
    "CohereLabs/tiny-aya-water",
    "CohereLabs/tiny-aya-earth",
    # Larger siblings.
    "CohereLabs/aya-expanse-8b",
    "CohereLabs/aya-expanse-32b",
    # Other Cohere releases that may not be gated.
    "CohereForAI/aya-23-8B",
    "CohereForAI/aya-23-35B",
    "CohereForAI/aya-expanse-8b",
    "CohereLabs/c4ai-command-r7b-12-2024",
    "CohereForAI/c4ai-command-r7b-12-2024",
    "CohereLabs/c4ai-command-r-plus-08-2024",
]


def probe(repo: str) -> dict:
    out = {"repo": repo, "gated": None, "private": None, "error": None, "anon_config_ok": None}
    try:
        req = urllib.request.Request(
            f"https://huggingface.co/api/models/{repo}",
            headers={"User-Agent": "phantom-safety-gate-probe"},
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        out["gated"] = data.get("gated")
        out["private"] = data.get("private")
        out["downloads"] = data.get("downloads")
    except urllib.error.HTTPError as exc:
        out["error"] = f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        out["error"] = type(exc).__name__

    # Second, independent check: can config.json be fetched anonymously?
    try:
        req = urllib.request.Request(
            f"https://huggingface.co/{repo}/resolve/main/config.json",
            headers={"User-Agent": "phantom-safety-gate-probe"},
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            out["anon_config_ok"] = resp.status == 200
    except urllib.error.HTTPError as exc:
        out["anon_config_ok"] = False
        out["config_error"] = f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        out["anon_config_ok"] = False
        out["config_error"] = type(exc).__name__
    return out


def main() -> int:
    print("=" * 92)
    print("HUGGING FACE GATING PROBE (anonymous)")
    print("=" * 92)
    print(f"{'repo':46s} {'gated':>8s} {'private':>8s} {'config':>8s}  note")
    print("-" * 92)

    results = [probe(r) for r in CANDIDATES]
    usable = []
    for r in results:
        gate = str(r["gated"])
        priv = str(r["private"])
        ok = str(r["anon_config_ok"])
        note = r.get("error") or r.get("config_error") or ""
        if r["gated"] is False and not r["private"]:
            note = (note + " USABLE ANONYMOUSLY").strip()
            usable.append(r["repo"])
        print(f"{r['repo']:46s} {gate:>8s} {priv:>8s} {ok:>8s}  {note}")

    print("-" * 92)
    gated = [r["repo"] for r in results if r["gated"] is not False]
    print(f"gated or unreachable: {len(gated)}/{len(results)}")
    for g in gated:
        print(f"  - {g}")
    if usable:
        print(f"\nusable without credentials ({len(usable)}):")
        for u in usable:
            print(f"  + {u}")
        print("\nRESULT: at least one candidate is downloadable anonymously.")
        return 0
    print("\nRESULT: every candidate requires authentication. Training is blocked on an "
          "HF account that has accepted the licence terms.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())