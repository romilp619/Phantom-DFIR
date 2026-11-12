#!/usr/bin/env bash
# Does the currently-running job overwrite the already-good adapter?
# This is the risk that decides whether to keep waiting or kill PID 413 now.
set -u

echo "=== output_dir in the running script ==="
grep -n 'output_dir' /opt/train_run.py 2>/dev/null | head -6

echo
echo "=== where the GOOD adapter lives and when it was written ==="
stat -c '%y  %n' /opt/out/tiny-aya-phantom/adapter/adapter_model.safetensors 2>/dev/null

echo
echo "=== when the running job started ==="
ps -o lstart=,pid=,etime= -p 413 2>/dev/null

echo
echo "=== how far along is it now ==="
grep -aoE '^ *[0-9]+%\|[^|]*\| +[0-9]+/[0-9]+ \[[0-9:]+<[0-9:]+' /opt/train_run.log 2>/dev/null | tail -3
tail -c 400 /opt/train_run.log 2>/dev/null | tr '\r' '\n' | tail -4

echo
echo "=== free RAM + VRAM right now ==="
free -g | head -2
nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu,power.draw --format=csv,noheader