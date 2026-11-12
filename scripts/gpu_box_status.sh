#!/usr/bin/env bash
# Report the state of the training run on the gaming laptop, run REMOTELY.
# Kept as a file because pwsh mangles ; and || in ssh command strings.
set -u

echo "=== GPU ==="
nvidia-smi --query-gpu=name,memory.total,memory.used,utilization.gpu,power.draw,temperature.gpu \
  --format=csv,noheader 2>/dev/null || echo "no nvidia-smi"

echo
echo "=== training process ==="
pgrep -af 'train_run|python' 2>/dev/null | head -5 || echo "no python process"

echo
echo "=== log tail ==="
for f in /root/train_out.log /tmp/train_out.log /opt/train_out.log; do
  if [ -f "$f" ]; then
    echo "--- $f ($(wc -l < "$f") lines, $(stat -c %y "$f"))"
    tail -6 "$f"
    break
  fi
done
if [ ! -f /root/train_out.log ] && [ ! -f /tmp/train_out.log ] && [ ! -f /opt/train_out.log ]; then
  echo "no train_out.log found; searching:"
  find / -maxdepth 3 -name 'train_out.log' -o -maxdepth 3 -name '*.log' -path '*train*' 2>/dev/null | head -5
fi

echo
echo "=== memory ==="
free -g | head -3

echo
echo "=== checkpoints written ==="
find / -maxdepth 5 -name '*.safetensors' -o -maxdepth 5 -name 'adapter_model*' 2>/dev/null | head -8 || echo none
