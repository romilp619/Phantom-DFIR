#!/usr/bin/env bash
# Copy the adapter out of WSL onto the Windows filesystem so scp can reach it.
# /mnt/c/... is the Windows C: drive as seen from inside WSL.
set -u

SRC=/opt/out/tiny-aya-phantom/adapter
WINDIR=/mnt/c/Users/Owner/Downloads/redirect/phantom-safety/artifacts/tiny-aya-phantom-adapter
HOSTDIR=/mnt/c/Users/Moo/adapter-out

echo "=== stage 1: copy to a Windows-visible path in WSL ==="
mkdir -p "$HOSTDIR"
cp -a "$SRC"/. "$HOSTDIR"/ 2>&1 && echo "copied to $HOSTDIR"
ls -la "$HOSTDIR" | head -8

echo
echo "=== also try the direct /mnt/c repo path ==="
mkdir -p "$WINDIR" 2>&1
cp -a "$SRC"/. "$WINDIR"/ 2>&1 && echo "copied to $WINDIR"
ls -la "$WINDIR" | head -8

echo
echo "=== checksums ==="
sha256sum "$SRC/adapter_model.safetensors" "$HOSTDIR/adapter_model.safetensors" 2>/dev/null