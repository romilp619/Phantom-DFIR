#!/usr/bin/env bash
# Engine import smoke against a given tree. $1 = path to the tree to test.
set -u

TREE="${1:?usage: smoke_engine_imports.sh <tree-path-wsl>}"
# Interpreter: PHANTOM_PY overrides; otherwise the original eval venv when it is
# usable, else the active python3. The hardcoded /root path is not readable by a
# normal user, which made every module report a permission error rather than an
# import result.
PY="${PHANTOM_PY:-}"
if [ -z "$PY" ]; then
  if [ -x /root/phantom-eval-venv/bin/python ]; then
    PY=/root/phantom-eval-venv/bin/python
  else
    PY=$(command -v python3 || command -v python)
  fi
fi
[ -n "$PY" ] || { echo "no python interpreter found; set PHANTOM_PY"; exit 2; }
echo "python: $PY"

cd "$TREE" || { echo "cannot cd to $TREE"; exit 2; }
echo "tree: $(pwd)"
echo "head: $(git rev-parse --short HEAD 2>/dev/null || echo 'not a repo')"

MODULES=(
  agents agents.collector agents.evidence agents.investigator agents.orchestrator
  agents.reporter agents.skeptic
  benchmark benchmark_reports config
  correlation correlation.confidence correlation.mitre correlation.mitre_rules
  correlation.timeline
  disk_correlator forensic_reasoning_patch main mcpserver.mcp_server phantom_router
  state tools tools.accuracy tools.legitimacy_engine tools.llm_provider
  tools.memory_triage tools.skills_loader tools.trusted_resources tools.vol2_tools
  tools.vol3_tools
)

ok=0
fail=0
for m in "${MODULES[@]}"; do
  if err=$("$PY" -c "import importlib; importlib.import_module('$m')" 2>&1); then
    ok=$((ok+1))
  else
    fail=$((fail+1))
    last=$(printf '%s\n' "$err" | grep -E '^[A-Za-z_.]*(Error|Exception)' | tail -1)
    [ -z "$last" ] && last=$(printf '%s\n' "$err" | tail -1)
    printf '  FAIL  %-32s %s\n' "$m" "${last:0:95}"
  fi
done

echo "engine modules : ${#MODULES[@]}"
echo "  clean        : $ok"
echo "  failed       : $fail"
[ "$fail" -eq 0 ] && echo "RESULT: no collisions"