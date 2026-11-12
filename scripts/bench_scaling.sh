#!/bin/bash
# Measure guard scan time against artifact size, looking for superlinear growth.
# A scanner that degrades faster than linearly on large evidence is a denial of
# service against the analyst: one oversized artifact stalls the whole batch.
#
# The Windows build produces phantom-guard.exe. Getting that wrong silently times a
# nonexistent file and reports 0 ms, so the path is checked before any timing runs.
set -u
VENV="$HOME/phantom-eval-venv/bin"
GUARDDIR="/mnt/c/Users/Owner/Downloads/redirect/phantom-safety/phantom-guard/target/release"
PROJ="/mnt/c/Users/Owner/Downloads/redirect/phantom-safety"

if [ -x "$GUARDDIR/phantom-guard" ]; then
    GUARD="$GUARDDIR/phantom-guard"
elif [ -x "$GUARDDIR/phantom-guard.exe" ]; then
    GUARD="$GUARDDIR/phantom-guard.exe"
else
    echo "guard binary not found in $GUARDDIR (looked for phantom-guard and .exe)"
    exit 2
fi
echo "guard: $GUARD"
echo
printf "%10s %10s %10s %8s\n" "size" "guard_ms" "python_ms" "ratio"
printf "%10s %10s %10s %8s\n" "-----" "--------" "---------" "-----"

for KB in 64 256 1024 4096 8192 16384; do
  N=$((KB * 1024))
  "$VENV/python" - "$N" > /tmp/p.json <<'PY'
import json, sys
n = int(sys.argv[1])
# Benign filler, no injection keywords: this isolates cost, not detection.
line = "PID 882 svchost.exe 0x0372 C:\\Windows\\System32\\svchost.exe 24 handles\n"
body = (line * (n // len(line) + 1))[:n]
json.dump({"id": "size", "text": body}, sys.stdout)
PY

  T0=$(date +%s%N)
  "$GUARD" scan < /tmp/p.json > /tmp/g.json 2>/dev/null
  GRC=$?
  T1=$(date +%s%N)
  GMS=$(( (T1 - T0) / 1000000 ))

  T0=$(date +%s%N)
  "$VENV/python" - <<'PY'
import json, sys
sys.path.insert(0, "/mnt/c/Users/Owner/Downloads/redirect/phantom-safety")
from phantom_ai_safety.evidence_scanner import scanner
p = json.load(open("/tmp/p.json"))
scanner.scan_artifact(p["id"], p["text"])
PY
  T1=$(date +%s%N)
  PMS=$(( (T1 - T0) / 1000000 ))

  # Sanity: the guard must have produced output for the size it timed.
  OUTLEN=$(wc -c < /tmp/g.json)
  RATIO=$("$VENV/python" -c "print(f'{$GMS/max($PMS,1):.2f}x')" 2>/dev/null || echo "?")
  printf "%10s %10s %10s %8s   rc=%s out=%sB\n" "${KB}KB" "$GMS" "$PMS" "$RATIO" "$GRC" "$OUTLEN"
done
rm -f /tmp/p.json /tmp/g.json
echo DONE