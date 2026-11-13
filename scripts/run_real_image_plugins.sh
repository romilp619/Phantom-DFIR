#!/bin/bash
# Run the Volatility plugins Phantom-DFIR's collection layer actually calls, on a
# real memory image, and save each output. This is the integration test that the
# synthetic red-team rows cannot provide: real plugin output, real formatting.
set -u
VENV="$HOME/phantom-eval-venv/bin"
IMG_DIR="/mnt/c/Users/Owner/Downloads/redirect/phantom-safety/test-images"
OUT_DIR="/mnt/c/Users/Owner/Downloads/redirect/phantom-safety/test-images/plugin-output"
IMG="$IMG_DIR/memdump.mem"

mkdir -p "$OUT_DIR"

# Note: in Volatility 3 the hive list plugin moved under the registry namespace.
# `windows.hivelist` does not exist and exits 2; `windows.registry.hivelist` works.
PLUGINS="windows.pslist windows.malfind windows.netscan windows.dlllist windows.cmdline windows.registry.hivelist windows.svcscan"

for p in $PLUGINS; do
    OUT="$OUT_DIR/${p}.txt"
    echo "--- $p ---"
    "$VENV/vol" -q -f "$IMG" "$p" > "$OUT" 2>"$OUT_DIR/${p}.err"
    RC=$?
    LINES=$(wc -l < "$OUT")
    BYTES=$(wc -c < "$OUT")
    echo "  rc=$RC  lines=$LINES  bytes=$BYTES"
    if [ "$LINES" -gt 0 ]; then
        head -3 "$OUT" | sed 's/^/    /'
    else
        head -3 "$OUT_DIR/${p}.err" | sed 's/^/    ERR: /'
    fi
done

echo
echo "=== outputs written ==="
ls -la "$OUT_DIR"/*.txt 2>/dev/null | awk '{print "  " $5 " bytes  " $9}'
echo "DONE"