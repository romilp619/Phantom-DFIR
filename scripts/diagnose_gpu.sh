#!/bin/bash
# Why did the training step time go from 28 s/it to 242 s/it at step 218?
# Look for thermal throttling, a competing process, or memory pressure.
nvidia-smi --query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,power.limit,clocks.sm,clocks.max.sm --format=csv
echo
echo "--- compute processes ---"
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv
echo
echo "--- throttle reasons ---"
nvidia-smi -q -d PERFORMANCE 2>/dev/null | grep -iE "clocks (event|throttle) reasons|Idle|Applications Clocks|SW Power Cap|HW Slowdown|SW Thermal|HW Thermal|Sync Boost" | head -14
echo
echo "--- memory and swap ---"
free -g
echo
echo "--- load ---"
uptime
echo
echo "--- top cpu ---"
ps aux --sort=-%cpu | head -6
echo DONE