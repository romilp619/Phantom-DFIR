"""Final CuratorKIT run with the two corrections the probe revealed.

Correction 1: clean_transforms strip_html OFF.
  The TextCleaner strips tag-shaped text and reported doing so on 1900 of 1900 rows. In
  this dataset the angle-bracket markers are evidence anchors, not HTML, so the default
  silently deletes the structure the model is meant to learn. The toolkit warns about this
  in its log, which is good, but only if the log is read.

Correction 2: preserve row identity.
  DataSample.id came back as a generated UUID, not the project's own row id, so every row
  lost its provenance. The projection now carries the original id and family through, and
  the result is verified afterwards rather than assumed.
"""
from __future__ import annotations

import json
import time

from curatorkit import Curator, CuratorConfig, JSONLReader

TRAIN = "/mnt/c/Users/Moo/phantom-data/train.jsonl"
PROJ = "/opt/phantom_alpaca_ids.jsonl"
REPORT = "/opt/curatorkit_final.json"

# ---------------------------------------------------------------- projection
stats = {"rows": 0, "ids_in": 0}
with open(TRAIN, "r", encoding="utf-8") as src, open(PROJ, "w", encoding="utf-8") as dst:
    for line in src:
        rec = json.loads(line)
        by = {m.get("role"): m.get("content", "") for m in rec.get("messages") or []}
        row = {
            "instruction": by.get("system", "").strip(),
            "input": by.get("user", "").strip(),
            "output": by.get("assistant", "").strip(),
            "id": rec.get("id"),                       # provenance
            "family": rec.get("family"),               # provenance
        }
        if rec.get("id"):
            stats["ids_in"] += 1
        dst.write(json.dumps(row) + "\n")
        stats["rows"] += 1
print("projection:", stats)
assert stats["ids_in"] == stats["rows"], "some rows had no id"

FIELDS = (getattr(CuratorConfig, "model_fields", None)
          or getattr(CuratorConfig, "__dataclass_fields__", None) or {})
ALLOWED = set(FIELDS)


def build(**wanted):
    return CuratorConfig(**{k: v for k, v in wanted.items() if k in ALLOWED})


def run(label, **wanted):
    t0 = time.time()
    res = Curator(build(dataset=PROJ, format="alpaca", write_hf_readme=False,
                        output_dir=f"/opt/ck_{label}", name=label, **wanted)).run()
    el = time.time() - t0
    p = len(res.passed or [])
    r = len(res.rejected or [])
    print(f"\n[{label}] {el:.2f}s passed={p} rejected={r}")
    print(f"[{label}] stages={json.dumps(res.stage_counts, default=str)}")
    return res, el, p, r


# ---------------------------------------------------------------- A: default clean
print("\n=== A: default cleaning (for comparison) ===")
resA, elA, pA, rA = run("clean_default")

# ---------------------------------------------------------------- B: strip_html off
print("\n=== B: strip_html disabled ===")
overB = {}
if "clean_transforms" in ALLOWED:
    overB["clean_transforms"] = {"strip_html": False}
else:
    print("  clean_transforms NOT declared in this version")
    print("  available clean fields:",
          [k for k in FIELDS if k.startswith("clean")])
resB, elB, pB, rB = run("clean_off", **overB)

# ---------------------------------------------------------------- verify markers survive
def marker_survival(samples):
    """Count how many surviving samples still carry an angle-bracket evidence marker."""
    hit = 0
    for s in samples:
        text = " ".join(str(getattr(s, k, "") or "") for k in ("instruction", "input"))
        if "<" in text and ">" in text:
            hit += 1
    return hit

survA = marker_survival(resA.passed or [])
survB = marker_survival(resB.passed or [])
print(f"\nmarkers surviving default clean : {survA}/{pA}")
print(f"markers surviving strip_html off: {survB}/{pB}")

# ---------------------------------------------------------------- provenance check
def id_check(samples, label):
    vals = [getattr(s, "id", None) for s in samples[:200]]
    uuids = sum(1 for v in vals if v and len(str(v)) == 36 and str(v).count("-") == 4)
    print(f"{label}: {uuids}/{len(vals)} sampled ids look like generated UUIDs")
    sample = [str(v) for v in vals if v][:3]
    print(f"{label}: sample ids {sample}")
    return uuids

idA = id_check(resA.passed or [], "default")
idB = id_check(resB.passed or [], "strip_off")

report = {
    "toolkit": "curatorkit",
    "version": "0.1.24",
    "input_rows": stats["rows"],
    "run_default_clean": {
        "seconds": round(elA, 2), "passed": pA, "rejected": rA,
        "stages": resA.stage_counts,
        "rows_retaining_evidence_marker": survA,
        "ids_that_are_generated_uuids": f"{idA}/200",
    },
    "run_strip_html_off": {
        "seconds": round(elB, 2), "passed": pB, "rejected": rB,
        "stages": resB.stage_counts,
        "rows_retaining_evidence_marker": survB,
        "ids_that_are_generated_uuids": f"{idB}/200",
    },
    "findings": [
        "format must be an explicit DataFormat member; an invalid string like 'jsonl' "
        "causes 100% rejection and RejectedSample carries no reason",
        "default TextCleaner removes angle-bracket evidence markers from every row, "
        "which deletes the semantic structure this dataset exists to teach",
        "DataSample.id is a generated UUID, so row provenance needs carrying separately",
        "injection_rate alone produced no observable injected rows and diagnostics was "
        "empty, so it needs injection_types to be meaningful",
    ],
}
with open(REPORT, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
print(f"\nwrote {REPORT}")
print("FINAL_DONE")