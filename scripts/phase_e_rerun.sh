#!/usr/bin/env bash
# Phase E re-run against the integrated tip AFTER the parallel agent's commit.
#
# Verifies that the merge did not regress anything: the pytest suite, the engine import
# smoke, and the integration-integrity counts. Run from anywhere; it clones for itself.
set -u

ROOT=/mnt/c/Users/Owner/Downloads/redirect/phantom-safety
WORK=$ROOT/artifacts/phaseE2
PY=/root/phantom-eval-venv/bin/python

rm -rf "$WORK"
mkdir -p "$WORK"

echo "=== cloning the current HEAD ==="
git clone -q "$ROOT" "$WORK/repo" || { echo "clone failed"; exit 2; }
cd "$WORK/repo" || exit 2
echo "HEAD: $(git rev-parse --short HEAD) $(git log --format=%s -1)"

echo
echo "=== 1. build the Rust guard ==="
cd "$WORK/repo/phantom-guard" || exit 2
if command -v cargo >/dev/null 2>&1; then
  cargo build --release 2>&1 | tail -2
else
  for c in /mnt/c/Users/Owner/.cargo/bin/cargo.exe "$HOME/.cargo/bin/cargo"; do
    [ -x "$c" ] && { "$c" build --release 2>&1 | tail -2; break; }
  done
fi
ls -la target/release/phantom-guard* 2>/dev/null | head -2

echo
echo "=== 2. pytest suite ==="
cd "$WORK/repo" || exit 2
"$PY" -m pytest tests/ -q -p no:cacheprovider 2>&1 | tail -3

echo
echo "=== 3. engine import smoke (31 original modules) ==="
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
ok=0; fail=0
for m in "${MODULES[@]}"; do
  err=$("$PY" -c "import importlib; importlib.import_module('$m')" 2>&1)
  if [ $? -eq 0 ]; then
    ok=$((ok+1))
  else
    fail=$((fail+1))
    last=$(printf '%s\n' "$err" | grep -E '^[A-Za-z_.]*(Error|Exception)' | tail -1)
    [ -z "$last" ] && last=$(printf '%s\n' "$err" | tail -1)
    printf '  FAIL  %-32s %s\n' "$m" "${last:0:95}"
  fi
done
echo "  clean: $ok / ${#MODULES[@]}   failed: $fail"

echo
echo "=== 4. report claims gate ==="
"$PY" scripts/verify_report_claims.py 2>&1 | tail -2

echo
echo "=== 5. integration integrity (84 originals) ==="
"$PY" scripts/verify_integration_integrity.py 2>&1 | grep -E "byte-identical|differing|missing|additive|syntax" | head -6
