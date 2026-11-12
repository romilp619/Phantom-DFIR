# Correction to commit f104af1

`f104af1` listed this line under "Measured effect" of its own changes:

    scripts/verify_integration_integrity.py  86/88 byte-identical, 0 syntax errors

That is misleading. `scripts/verify_integration_integrity.py` compares two
**fixed commits** named in its source, `ORIG = "3005762"` and
`INTEG = "2fa27b6"`. It never reads the working tree or `HEAD`, so its output is
identical before and after any later commit and it does not validate `f104af1`,
this commit, or anything else after `2fa27b6`. Its 86/88 result remains a
correct and useful statement about the integration commit itself. It is not
evidence about subsequent changes.

## What the cleanup commits actually changed, measured against 5e8340b

Original forensic files (present in `3005762`):

| File | Change | Behaviour |
|---|---|---|
| `README.md` | de-duplicated install steps, one architecture diagram | documentation |
| `ARCHITECTURE.md` | stale ASCII diagram replaced, AI-safety section added | documentation |
| `requirements.txt` | declared `pytest`, documented optional GPU extras | declarations only |
| `disk_correlator.py` | +50 lines, comment only | **syntax tree identical** |
| `mcpserver/mcp_server.py` | +21 lines in the `except ImportError` branch | syntax tree differs by design; the `try` branch is untouched, so the path taken when `mcp` is installed is unchanged |
| `correlation/__pycache__/*.pyc` (x4) | untracked, files kept on disk | none |

Additive files:

| File | Change |
|---|---|
| `phantom_ai_safety/harness/env.py` | `phantom_root()` defaults to the repository instead of another machine's path |
| `scripts/smoke_engine_imports.sh` | interpreter is resolvable; `$?` test after assignment fixed |

## Evidence that does track these changes

Run on this tree, same interpreter before and after:

| Check | Before | After |
|---|---|---|
| `scripts/smoke_engine_imports.sh` (30 engine modules) | 0 clean / 30 failed | 30 clean / 0 failed |
| `tests/` via pytest | 91 passed, 1 failed, 4 errors | 92 passed, 0 failed, 4 errors |
| `py_compile`, all Python files | 0 failures | 0 failures |
| `scripts/verify_report_claims.py` | all figures match | all figures match |

The 4 remaining test errors are `ModuleNotFoundError: No module named
'langchain_core'` in the interpreter that has `pytest`. The interpreter that has
`langchain_core` and `langgraph` has no `pytest`, which is why the two rows above
come from different interpreters. No forensic regression suite was run: that
needs a real memory or disk image, which is not present here.
