#!/usr/bin/env bash
# Preserve the good adapter before the running job overwrites it, then report state.
# Backup is read-only-safe: we only COPY into a new timestamped dir.
set -u

SRC=/opt/out/tiny-aya-phantom/adapter
DST=/opt/out/PRESERVED-adapter-20261112-0336

echo "=== before: source ==="
ls -la "$SRC" 2>/dev/null | head -8

if [ ! -d "$SRC" ]; then
  echo "SOURCE MISSING - nothing to preserve"
  exit 0
fi

if [ -d "$DST" ]; then
  echo "backup already exists at $DST, verifying..."
else
  echo
  echo "=== copying to $DST ==="
  cp -a "$SRC" "$DST" && echo "copied"
fi

echo
echo "=== after: backup ==="
ls -la "$DST" 2>/dev/null | head -8

echo
echo "=== integrity: sha256 of both ==="
sha256sum "$SRC/adapter_model.safetensors" "$DST/adapter_model.safetensors" 2>/dev/null

echo
echo "=== which output paths exist (is the running job pointed at our SRC?) ==="
grep -nE '^(OUT|OUTPUT)|OUT *=' /opt/train_run.py 2>/dev/null | head -5