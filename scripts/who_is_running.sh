#!/usr/bin/env bash
# Identify the running eval processes so we kill only OUR duplicate, never the
# other agent's work. Prints pid, parent pid, elapsed seconds, and the command.
set -u

echo "=== eval_model processes ==="
ps -eo pid,ppid,etimes,stat,args | awk 'NR==1 || /eval_model/'

echo
echo "=== all python with elapsed time ==="
ps -eo pid,ppid,etimes,args | awk 'NR==1 || /python/'

echo
echo "=== files in /tmp from my runs ==="
ls -la /tmp/adapter_eval*.json /tmp/rule_baseline.json 2>/dev/null || echo "none"

echo
echo "=== GPU ==="
nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu,power.draw --format=csv,noheader 2>/dev/null
nvidia-smi --query-compute-apps=pid,used_memory --format=csv,noheader 2>/dev/null | head -5