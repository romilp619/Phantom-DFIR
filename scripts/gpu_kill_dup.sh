#!/usr/bin/env bash
# Stop the duplicate training run (PID 413) that targets the same output_dir as the
# already-good adapter, and free the 4060 for gaming.
set -u

PID=413

echo "=== before ==="
if kill -0 "$PID" 2>/dev/null; then
  echo "PID $PID alive: $(ps -o etime=,cmd= -p $PID 2>/dev/null)"
else
  echo "PID $PID already gone"
fi

echo
echo "=== terminate ==="
kill -TERM "$PID" 2>/dev/null && echo "sent SIGTERM"
sleep 4

if kill -0 "$PID" 2>/dev/null; then
  echo "still alive, sending SIGKILL"
  kill -9 "$PID" 2>/dev/null
  sleep 3
fi

echo
echo "=== after ==="
if kill -0 "$PID" 2>/dev/null; then
  echo "STILL RUNNING - investigate"
else
  echo "PID $PID GONE"
fi

echo
echo "=== any other training python left? ==="
pgrep -af 'train_run' 2>/dev/null || echo "no train_run processes"

echo
echo "=== GPU now ==="
nvidia-smi --query-gpu=memory.used,memory.total,utilization.gpu,power.draw --format=csv,noheader 2>/dev/null

echo
echo "=== preserved adapter still intact? ==="
sha256sum /opt/out/PRESERVED-adapter-20261112-0336/adapter_model.safetensors 2>/dev/null
ls -la /opt/out/PRESERVED-adapter-20261112-0336/ 2>/dev/null | head -6