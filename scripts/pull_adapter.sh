#!/usr/bin/env bash
# Pull the trained LoRA adapter from the GPU box to this repo.
#
# The adapter is ~115 MB (32 MB compressed). It is deliberately NOT committed; see
# .gitignore. Re-running the training job reproduces it in ~22 minutes.
#
# Usage:  scripts/pull_adapter.sh [user@host]
set -eu

HOST="${1:-Moo@100.96.130.88}"
KEY="${SSH_KEY:-$HOME/.dsh/mc-keys/id_rsa}"
REMOTE_WIN="C:/Users/Moo/adapter-out"
DEST="artifacts/tiny-aya-phantom-adapter"

echo "=== pulling from $HOST ($REMOTE_WIN) ==="
mkdir -p "$DEST"

# The adapter lives inside WSL on the training box. /mnt/c there is the BOX's own C:,
# not this machine's, so we stage it onto the box's Windows filesystem first and scp
# from that. Copying straight out of WSL with scp fails: the path does not exist to
# the Windows ssh server.
ssh -i "$KEY" -o BatchMode=yes "$HOST" \
  "wsl -d Ubuntu -u root bash -c 'mkdir -p /mnt/c/Users/Moo/adapter-out && cp -a /opt/out/tiny-aya-phantom/adapter/. /mnt/c/Users/Moo/adapter-out/ && echo staged'"

echo "=== scp ==="
scp -i "$KEY" -o BatchMode=yes "$HOST:$REMOTE_WIN/*" "$DEST/"

echo "=== verify ==="
ls -la "$DEST"
sha256sum "$DEST/adapter_model.safetensors" 2>/dev/null || \
  powershell -Command "Get-FileHash '$DEST/adapter_model.safetensors' -Algorithm SHA256"

echo
echo "known-good sha256 (2026-11-12, loss 1.465):"
echo "  04cefc93314b39ed367cc8d93a1204104c3b6eb4e9442bb49dd71554933bfdaa"