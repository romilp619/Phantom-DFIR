#!/bin/bash
# Parse-check every Python file in the repo.
#
# Written as a file rather than an inline -c because nested quoting through
# pwsh -> wsl -> bash silently ate the loop variable and reported every file as
# failing. The tool should be more trustworthy than the thing it checks.
set -u
VENV="$HOME/phantom-eval-venv/bin"
PROJ="/mnt/c/Users/Owner/Downloads/redirect/phantom-safety"

cd "$PROJ" || exit 2

ok=0
bad=0
while IFS= read -r f; do
    if "$VENV/python" -c 'import ast,sys; ast.parse(open(sys.argv[1],encoding="utf-8").read())' "$f" 2>/dev/null; then
        ok=$((ok + 1))
    else
        bad=$((bad + 1))
        echo "  PARSE FAIL: $f"
        "$VENV/python" -c 'import ast,sys; ast.parse(open(sys.argv[1],encoding="utf-8").read())' "$f" 2>&1 | tail -2 | sed 's/^/      /'
    fi
done < <(find . -name "*.py" -not -path "./.git/*" -not -path "*/__pycache__/*" -not -path "./phantom-guard/*" | sort)

echo "python files: ok=$ok bad=$bad"
[ "$bad" -eq 0 ]