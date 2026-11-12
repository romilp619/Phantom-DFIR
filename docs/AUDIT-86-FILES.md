# PHANTOM DFIR - Audit of the 86 Files Absent from the Remote Tip

Base (original): `3005762` - 88 files

Remote tip: `8017d1a` - 115 files

Only in original: **86**  |  only in remote: 113  |  shared: 2


## 1. The complete 86-file list, categorised


### Original forensic functionality (41)

| # | path |
|---|---|
| 1 | `agents/__init__.py` |
| 2 | `agents/collector.py` |
| 3 | `agents/evidence.py` |
| 4 | `agents/investigator.py` |
| 5 | `agents/orchestrator.py` |
| 6 | `agents/reporter.py` |
| 7 | `agents/skeptic.py` |
| 8 | `benchmark.py` |
| 9 | `benchmark_reports.py` |
| 10 | `config.py` |
| 11 | `correlation/__init__.py` |
| 12 | `correlation/__pycache__/__init__.cpython-310.pyc` |
| 13 | `correlation/__pycache__/confidence.cpython-310.pyc` |
| 14 | `correlation/__pycache__/mitre.cpython-310.pyc` |
| 15 | `correlation/__pycache__/timeline.cpython-310.pyc` |
| 16 | `correlation/confidence.py` |
| 17 | `correlation/mitre.py` |
| 18 | `correlation/mitre_rules.py` |
| 19 | `correlation/timeline.py` |
| 20 | `disk_correlator.py` |
| 21 | `forensic_reasoning_patch.py` |
| 22 | `logs/final_runs/ali_hadi_encrypt_them_all.log` |
| 23 | `logs/final_runs/cfreds_data_leakage.log` |
| 24 | `logs/final_runs/m57_jean_phishing.log` |
| 25 | `logs/final_runs/memory_self_correction.log` |
| 26 | `logs/final_runs/nitroba_harassment_pcap.log` |
| 27 | `logs/final_runs/sysinternals_case.log` |
| 28 | `main.py` |
| 29 | `mcpserver/mcp_server.py` |
| 30 | `phantom_router.py` |
| 31 | `state.py` |
| 32 | `test_mcp.py` |
| 33 | `tools/__init__.py` |
| 34 | `tools/accuracy.py` |
| 35 | `tools/legitimacy_engine.py` |
| 36 | `tools/llm_provider.py` |
| 37 | `tools/memory_triage.py` |
| 38 | `tools/skills_loader.py` |
| 39 | `tools/trusted_resources.py` |
| 40 | `tools/vol2_tools.py` |
| 41 | `tools/vol3_tools.py` |

### Documentation (20)

| # | path |
|---|---|
| 1 | `ACCURACY_REPORT.md` |
| 2 | `ARCHITECTURE.md` |
| 3 | `BENCHMARK_MATRIX.md` |
| 4 | `DATASET.md` |
| 5 | `JUDGE_READINESS_CHECKLIST.md` |
| 6 | `PROJECT_DESCRIPTION.md` |
| 7 | `benchmark_results/README.md` |
| 8 | `benchmarks/README.md` |
| 9 | `logs/README.md` |
| 10 | `logs/final_runs/memory_self_correction_report.md` |
| 11 | `requirements.txt` |
| 12 | `skills/credential-dumping.md` |
| 13 | `skills/indicators-of-compromise.md` |
| 14 | `skills/lateral-movement.md` |
| 15 | `skills/living-off-the-land.md` |
| 16 | `skills/memory-forensics.md` |
| 17 | `skills/mitre-attack-mapping.md` |
| 18 | `skills/persistence.md` |
| 19 | `skills/process-injection.md` |
| 20 | `skills/rootkit-detection.md` |

### Configuration and tooling (24)

| # | path |
|---|---|
| 1 | `.gitattributes` |
| 2 | `LICENSE` |
| 3 | `benchmark_results/all_cases_benchmark_summary.json` |
| 4 | `benchmark_results/cfreds_benchmark_result.json` |
| 5 | `benchmark_results/encrypt_them_all_benchmark_result.json` |
| 6 | `benchmark_results/jean_benchmark_result.json` |
| 7 | `benchmark_results/nitroba_benchmark_result.json` |
| 8 | `benchmark_results/sysinternals_benchmark_result.json` |
| 9 | `benchmarks/ground_truth_cases.json` |
| 10 | `ground_truth_base_admin.json` |
| 11 | `install.sh` |
| 12 | `logs/final_runs/memory_self_correction_execution_log.json` |
| 13 | `logs/final_runs/memory_self_correction_report.json` |
| 14 | `memory_debug/cmdline.parsed.json` |
| 15 | `memory_debug/cmdscan.parsed.json` |
| 16 | `memory_debug/consoles.parsed.json` |
| 17 | `memory_debug/getsids.parsed.json` |
| 18 | `memory_debug/malfind.parsed.json` |
| 19 | `memory_debug/netscan.parsed.json` |
| 20 | `memory_debug/pslist.parsed.json` |
| 21 | `memory_debug/psscan.parsed.json` |
| 22 | `memory_debug/pstree.parsed.json` |
| 23 | `memory_debug/svcscan.parsed.json` |
| 24 | `memory_debug/timeliner.parsed.json` |

### Binary asset (1)

| # | path | note |
|---|---|---|
| 1 | `architecture.png` | 533,340 bytes; the original README's architecture figure |

> Classification note: `requirements.txt` was placed under Documentation by the
> path-based matcher (it matched `.txt`). It belongs to **Configuration and tooling**.
> Corrected totals: Documentation 19, Configuration and tooling 25.

## 2. Category totals

Every one of the 86 files belongs to the **original PHANTOM DFIR** project. None of
them is an AI Red Teaming file - that half lives entirely on the other history.

| category | files | belongs to original PHANTOM DFIR? |
|---|---|---|
| Original forensic functionality | 41 | yes |
| Configuration and tooling | 25 | yes |
| Documentation | 19 | yes |
| Binary asset | 1 | yes |
| AI Red Teaming functionality | **0** | n/a - the AI half is the 113 files that are only in the remote |

## 3. Engine completeness in the original history

Python files in the original tree: 31


Every capability module of the original engine is present in `3005762`:

- memory forensics: 3/3 present
- disk forensics: 2/2 present
- IOC / threat intel: 2/2 present
- routing / skills: 2/2 present
- threat scoring: 3/3 present
- agents: 3/3 present
- benchmarks: 2/2 present
- reporting / entry: 3/3 present
- packaging: 2/2 present

## 4. Overlapping paths

Total shared: 2

| path | status |
|---|---|
| `.gitignore` | differs |
| `README.md` | differs |

## 5. AI components that integrate without replacing anything

All paths in the remote tree that are NOT in the original are additive by definition.
Count: 113

Top-level prefixes:
| prefix | files |
|---|---|
| `scripts` | 46 |
| `phantom_ai_safety` | 23 |
| `docs` | 19 |
| `results` | 7 |
| `tests` | 6 |
| `phantom-guard` | 5 |
| `data` | 3 |
| `dashboard` | 2 |
| `articles` | 1 |
| `artifacts` | 1 |

**Conflicting implementations: there are none.** No path in the two histories is two
different versions of the same module. The 2 shared paths are a repository-level ignore
file and the top-level README - neither is code. This is the key structural fact that
makes the integration safe: the AI module is additive, not a competing implementation.

---

## 6. Recommended base commit

**`3005762`** - Romil's tip, "Simplify README architecture diagram".

Why this and not the remote tip:

- It is the **complete** original platform (88 files, 31 Python, every capability dir).
- Its tree is internally consistent: all 31 files parse, all 5 internal packages
  (`agents`, `config`, `correlation`, `state`, `tools`) resolve.
- The remote tip `8017d1a` is an incomplete *platform* (it is complete as an AI module).
  Basing on it would mean re-adding 86 files and re-creating the architecture by hand.

The integration commit **`2fa27b6`** already has this correct: its parent is `3005762`.

---

## 7. Proposed integration plan

Direction, fixed as stated: **PHANTOM DFIR is the base and primary application; the AI
Red Teaming / Safety work is added into it as modules.** No replacement either way.

### Phase A - Preserve (done, leave alone)
- `backup-before-recovery` branch and `phantom-backup.bundle` stay untouched.
- Branch `phantom-dfir-original` and tags in the other clone stay untouched.

### Phase B - Build the integrated tree
Already done at **`2fa27b6`** on branch `integrated/ai-safety`:

1. Start from `3005762` (Romil's tree, 88 files) - the base, unmodified.
2. Add the 113 AI-module paths that exist only in the remote tree.
3. Resolve the 2 overlapping files explicitly (see Phase D).
4. Result: 201 files, **115 changed, 56080 insertions, 0 deletions**.
5. 86 of Romil's 88 files are bit-identical to his originals.

### Phase C - Do NOT do these
- Do not merge the AI branch's root `1219666` into Romil's history. The roots are
  unrelated, so that would merge two whole trees and duplicate ~88 files.
- Do not cherry-pick the 26 AI commits individually. They assume their own tree layout;
  replaying them onto Romil's tree would conflict on every renamed path for no gain.
- Do not force-push `main` in either direction. That is what caused this.
- Do not rebase either history.

### Phase D - Conflict resolution strategy (all 2 conflicts)

| file | strategy | rationale |
|---|---|---|
| `.gitignore` | **union** of both rule sets | Each side ignores things the other does not. Romil's rules (`*.E01`, `*.img`, `*.raw`, `*.bak`, `base-admin-memory.img`) protect forensic images; the module's (`phantom-guard/target/`, `test-images/`, `artifacts/*-adapter/`, `*.safetensors`) keep 2 GB images and 115 MB adapters out of git. Verified: Romil's `*.raw` is present in the module's file, but **`*.E01`, `*.img`, `*.bak`, `base-admin-memory.img` are NOT** - so a naive "take theirs" would start committing forensic disk images. Union is required, not stylistic. |
| `README.md` | original as the source of truth, safety writeup appended | Keeps `# PHANTOM DFIR`, the 3 screenshots, both install paths and Steps 1-9; adds the safety sections below. Verified byte-exact prefix + footer preserved. |

### Phase E - Verify before approval
- `git diff --stat 3005762 2fa27b6` -> 0 deletions. Verified.
- Per-file blob SHA check -> 86/88 identical. Verified.
- Parse all Python -> 31/31 original, 89/89 integrated. Verified.
- Functional scan -> 0/1/1 findings benign/plain/base64. Verified.
- **Regression tests: NOT RUN.** No pytest on this machine. This is the one gate that is
  still open. Install pytest in a venv and run both suites before the change lands.

### Phase F - Land it, with review
1. Push `integrated/ai-safety` as a **branch**, never to `main`.
2. Open a PR with Romil as reviewer, base `main` = his `3005762`.
3. After his approval, fast-forward `main` to the integrated commit.

---

## 8. Incidental findings worth acting on

1. **`requirements.txt` is incomplete in the original.** The code imports
   `Evtx`, `fastapi`, `uvicorn`, `mcp`, `pyAesCrypt`, `langchain-anthropic`,
   `langchain-groq`, `langchain-openai`, and `langgraph`; the file pins only
   `langgraph`, `langchain-core`, `langchain-ollama`, `volatility3`, `fastapi`,
   `uvicorn`, `mcp`, `pefile`, `pyAesCrypt`. Missing pins: **`Evtx`, and the
   `langchain-anthropic` / `langchain-groq` / `langchain-openai` provider packages.**
   A clean install would fail on EVTX parsing. Pre-existing, not caused by the split.

2. **Four original files carry a UTF-8 BOM** (`agents/investigator.py`,
   `agents/orchestrator.py`, `agents/reporter.py`, `state.py`). Harmless to CPython but
   it breaks naive byte-offset tooling. Pre-existing; byte-identical to Romil's commits.

3. **`correlation/__pycache__/*.pyc` (4 files) are committed** in Romil's tree for
   Python 3.10. Build artifacts in git. Cosmetic, but they inflate the repo and go stale.

4. **`logs/` and `memory_debug/` are committed** (10 and 11 files) - real forensic run
   output for the CFReDS, Nitroba, SysInternals, and `encrypt_them_all` cases. Treat as
   evidence, not scratch: they are the benchmark traceability the judge pack cites.
   Do not delete as "generated files".

---

## 9. Audit status

| item | state |
|---|---|
| Backups | `backup-before-recovery` @ `25d3c75`; `phantom-backup.bundle` 3,588,216 bytes - both untouched |
| Merged / cherry-picked / reset | **nothing** |
| Files deleted | **none** |
| Base commit recommended | `3005762` |
| Integration already built | `2fa27b6` (branch `integrated/ai-safety`), 0 deletions |
| Conflicts | 2 (`.gitignore`, `README.md`), strategy above |
| Open gate | regression tests - no pytest installed |
