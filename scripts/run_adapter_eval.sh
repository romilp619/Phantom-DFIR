#!/usr/bin/env bash
# Run the adapter eval.
#
# The token stays in the file it already lives in and is never echoed. We export it
# in this shell using the read builtin, which avoids the nested-$() problem that
# broke earlier attempts through `bash -lc '...'`.
set -eu

REPO=/mnt/c/Users/Owner/Downloads/redirect/phantom-safety
TOK=/mnt/c/Users/Owner/.huggingface/token
LIMIT="${1:-40}"
OUT="${2:-/tmp/adapter_eval.json}"

cd "$REPO"

HF_TOKEN=$(cat "$TOK")
if [ ${#HF_TOKEN} -ne 37 ]; then
  echo "REFUSING: token length ${#HF_TOKEN}, expected 37. Not running." >&2
  exit 3
fi
export HF_TOKEN
export HUGGING_FACE_HUB_TOKEN="$HF_TOKEN"
echo "token loaded: 37 chars, prefix ${HF_TOKEN:0:3}***"

echo "=== eval: adapter=$REPO/artifacts/tiny-aya-phantom-adapter rows=$LIMIT ==="
set +e
"$HOME/phantom-eval-venv/bin/python" -m phantom_ai_safety.repair.eval_model \
  --adapter artifacts/tiny-aya-phantom-adapter \
  --heldout data/heldout.jsonl \
  --out "$OUT" \
  --limit "$LIMIT"
rc=$?
set -e
echo "exit: $rc"
exit $rc