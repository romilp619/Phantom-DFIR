#!/usr/bin/env bash
# Install transformers + peft into the phantom eval venv. Does NOT install torch
# (that comes from the system-level cu128 venv or is already present).
set -eu

VENV="$HOME/phantom-eval-venv"
PIP="$VENV/bin/pip"

echo "=== upgrading pip ==="
"$PIP" install --upgrade pip -q 2>&1

echo "=== transformers + peft (no torch download) ==="
"$PIP" install transformers peft --no-deps 2>&1 | tail -3

echo "=== verify ==="
"$VENV/bin/python" -c "
import transformers; print('transformers', transformers.__version__)
import peft; print('peft', peft.__version__)
" 2>&1

echo "done"