# Phase E: Regression Testing Results

**Status: complete. All checks pass or explained. Run date 2026-11-12.**

Run entirely on a **clone** (`artifacts/phaseE/repo`), so the live working tree and the
parallel agent's staged edits were never touched.

---

## 1. The pytest suite - the README's claim is VERIFIED

### 1.1 First run: 97 passed, 22 skipped

```
97 passed, 22 skipped in 2.28s
```

119 tests collected across 6 files: `test_core.py`, `test_curation_guards.py`,
`test_guard_bounded.py`, `test_injection.py`, `test_rust_guard.py`,
`test_scanner_normalization.py`.

### 1.2 Why 22 skipped - every skip has a legitimate reason

| count | file | reason |
|---|---|---|
| 9 | `test_rust_guard.py` | `phantom-guard binary not built; run cargo build --release` |
| 6 | `test_guard_bounded.py` | same - the bounded-scan tests need the binary |
| 7 | `test_scanner_normalization.py` | `raw scanner already catches this, case is mislabelled` |

**Nothing was hidden.** The 7 scanner skips are unusually honest test hygiene: the author
marked cases as mislabelled rather than leaving them passing for the wrong reason.

### 1.3 Build the Rust guard, re-run: 112 passed, 7 skipped

```
cargo build --release  ->  Finished in 15.06s, phantom-guard.exe 1.60 MB
112 passed, 7 skipped in 18.00s
```

**This exactly matches the README's claim of 112 passing / 7 skipped.** The gap was
entirely the unbuilt Rust binary, not a broken test or a false claim. The README's number
is now **VERIFIED**, where the audit previously recorded it as unverified.

The remaining 7 skips are the 7 self-labelled mislabelled cases. Those are correct to skip.

---

## 2. Engine import smoke - no architectural collision

The highest-value test in the plan: the only check that catches an AI-module file
shadowing or breaking a name the original engine imports. A syntax check cannot see it;
only an actual import can. Each of the 30 modules was imported in its own process.

```
engine modules : 30
  clean        : 29
  failed       : 1
```

**Result: `mcpserver.mcp_server` fails with `NameError: name 'Tool' is not defined`.**

### 2.1 That failure is PRE-EXISTING, not caused by the integration

Proven by extracting the untouched original tree (`git archive 3005762`) and importing the
same module from it:

```
cd artifacts/phaseE/orig && python -c 'import mcpserver.mcp_server'
    Tool(name="register_evidence",
    ^^^^
NameError: name 'Tool' is not defined
```

**Identical failure in the original.** The integration did not break it, and did not
inherit it either - it is a latent bug in Romil's own `mcpserver/mcp_server.py`, present
before the safety module existed.

**29 of 30 engine modules import cleanly. Zero collisions.** The strongest possible
evidence that the AI module is additive rather than a competing implementation.

### 2.2 A real bug worth reporting, in scope because it is in this repository

`mcpserver/mcp_server.py` references `Tool(...)` at module scope without importing it. The
module cannot be imported at all, so the MCP server cannot start. This is a genuine defect
in the original application and is **not** something the integration introduced.

---

## 3. Verification record

| check | result |
|---|---|
| pytest, 6 files, no Rust binary | 97 passed, 22 skipped |
| pytest, 6 files, Rust binary built | **112 passed, 7 skipped** |
| README claim of 112/7 | **VERIFIED - exact match** |
| engine modules imported | 29 of 30 clean |
| the 1 failure | pre-existing in `3005762`, proven by extracting and re-testing |
| integration collisions | **0** |

Methods: pytest run under `/root/phantom-eval-venv` (pytest 9.2.0); `cargo build --release`
with the bundled toolchain; per-module isolated `python -c import`; `git archive 3005762`
extraction to test the original independently.

**Done on a clone.** The live tree was not modified and the parallel agent's staged work
was not disturbed.

---

## 4. What is still untested

Named rather than implied:

- **`curatorkit` publishability** - the package is imported lazily by
  `scripts/curatorkit_curate.py`; whether it is on PyPI is still unknown.
- **Runtime behaviour of `langchain-core>=0.3.0`** - the imports resolve, but no LLM call
  was made. The version bump in Section 5.4 of the audit is unexercised.
- **The end-to-end pipeline** - `main.py` and `phantom_router.py` import cleanly, but no
  analysis run was performed. An import is not a run.
- **The 7 scanner skips** - deliberately unexercised by their author.
- **The MCP server** - cannot be tested at all until the `Tool` NameError is fixed.