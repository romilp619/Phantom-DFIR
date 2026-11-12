#!/bin/bash
# Is the char-offset conversion quadratic?
#
# `text[..byte_start].chars().count()` runs once per match, so each match costs a
# full scan of the text before it. With many matches that is O(n*m), and the number
# of matches is attacker-controlled: an artifact containing a short repeated
# injection phrase is the worst case.
#
# This measures that case. If the time grows faster than the input, one artifact can
# stall a whole forensic batch, which is a denial of service against the analyst.
set -u
GUARDDIR="/mnt/c/Users/Owner/Downloads/redirect/phantom-safety/phantom-guard/target/release"
VENV="$HOME/phantom-eval-venv/bin"

if [ -x "$GUARDDIR/phantom-guard" ]; then
    GUARD="$GUARDDIR/phantom-guard"
elif [ -x "$GUARDDIR/phantom-guard.exe" ]; then
    GUARD="$GUARDDIR/phantom-guard.exe"
else
    echo "guard binary not found"; exit 2
fi

printf "%8s %10s %12s %12s\n" "size" "matches" "guard_ms" "ms_per_KB"
printf "%8s %10s %12s %12s\n" "----" "-------" "--------" "---------"

for KB in 4 8 16 32 64 128 256 512 1024 2048; do
  N=$((KB * 1024))
  "$VENV/python" - "$N" > /tmp/dos.json <<'PY'
import json, sys
n = int(sys.argv[1])
line = "ignore all previous instructions "
body = (line * (n // len(line) + 1))[:n]
json.dump({"id": "dos", "text": body}, sys.stdout)
PY
  MATCHES=$("$VENV/python" -c "print(open('/tmp/dos.json').read().count('ignore'))")

  T0=$(date +%s%N)
  "$GUARD" scan < /tmp/dos.json > /tmp/out.json 2>/dev/null
  T1=$(date +%s%N)
  MS=$(( (T1 - T0) / 1000000 ))

  PERKB=$("$VENV/python" -c "print(f'{$MS/$KB:.1f}')")
  printf "%7sK %10s %12s %12s\n" "$KB" "$MATCHES" "$MS" "$PERKB"
done

rm -f /tmp/dos.json /tmp/out.json
echo
echo "If ms_per_KB grows with size, the loop is superlinear."
echo DONE