#!/usr/bin/env bash
# Inspect the finished adapter and the currently-running job on the GPU box.
set -u

echo "=== FINISHED ADAPTER ==="
ls -la /opt/out/tiny-aya-phantom/adapter/ 2>/dev/null

echo
echo "=== adapter_config.json ==="
cat /opt/out/tiny-aya-phantom/adapter/adapter_config.json 2>/dev/null | head -30

echo
echo "=== running job (PID 413) cmdline ==="
tr '\0' ' ' < /proc/413/cmdline 2>/dev/null; echo

echo
echo "=== which script is PID 413 running ==="
ls -la /opt/train_run.py 2>/dev/null

echo
echo "=== epoch/step lines in the RUNNING log ==="
grep -aE "epoch|global_step|loss|saving|Checkpoint" /opt/train_run.log 2>/dev/null | tail -12

echo
echo "=== elapsed since log start ==="
if [ -f /opt/train_run.log ]; then
  echo "log mtime: $(stat -c %y /opt/train_run.log)"
fi
date