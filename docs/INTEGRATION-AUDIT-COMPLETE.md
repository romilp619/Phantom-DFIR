# PHANTOM DFIR - Complete Integration Audit

Read-only audit. No implementation, no merge, no cherry-pick, no reset.
Prepared 2026-11-12. Awaiting approval before any implementation.

- Original (primary): `3005762` - 88 files, the PHANTOM DFIR forensic engine
- AI side: `8017d1a` - 115 files, the AI Red Teaming / Safety work
- Shared: 2 files. Only in original: 86. Only in AI side: 113.

---

## 1. Complete classification of all 86 files

All 86 belong to the **original PHANTOM DFIR**. None is an AI component.

### 1a. Original forensic functionality (41)

| # | path | role |
|---|---|---|
| 1 | `agents/__init__.py` | package |
| 2 | `agents/collector.py` | artifact collection agent |
| 3 | `agents/evidence.py` | evidence gathering / source keys |
| 4 | `agents/investigator.py` | primary investigator agent |
| 5 | `agents/orchestrator.py` | agent orchestration |
| 6 | `agents/reporter.py` | report generation agent |
| 7 | `agents/skeptic.py` | adversarial skeptic agent |
| 8 | `benchmark.py` | accuracy / FP / hallucination metrics |
| 9 | `benchmark_reports.py` | benchmark report builder |
| 10 | `config.py` | configuration |
| 11 | `correlation/__init__.py` | package |
| 12-15 | `correlation/__pycache__/*.pyc` (4) | **stale build artifacts, 3.10** |
| 16 | `correlation/confidence.py` | severity / confidence policy |
| 17 | `correlation/mitre.py` | MITRE ATT&CK mapping |
| 18 | `correlation/mitre_rules.py` | MITRE rule table |
| 19 | `correlation/timeline.py` | timeline reconstruction |
| 20 | `disk_correlator.py` | **disk / E01 / PCAP correlation (1.18 MB)** |
| 21 | `forensic_reasoning_patch.py` | forensic reasoning overrides |
| 22-27 | `logs/final_runs/*.log` (6) | CFReDS, Nitroba, SysInternals, encrypt_them_all, jean, memory_self_correction |
| 28 | `main.py` | CLI entry point |
| 29 | `mcpserver/mcp_server.py` | MCP server exposing the engine |
| 30 | `phantom_router.py` | unified analysis router |
| 31 | `state.py` | pipeline state |
| 32 | `test_mcp.py` | MCP smoke test |
| 33 | `tools/__init__.py` | package |
| 34 | `tools/accuracy.py` | accuracy helpers |
| 35 | `tools/legitimacy_engine.py` | legitimacy / false-positive scoring |
| 36 | `tools/llm_provider.py` | multi-provider LLM abstraction |
| 37 | `tools/memory_triage.py` | memory artifact triage |
| 38 | `tools/skills_loader.py` | skills loading |
| 39 | `tools/trusted_resources.py` | trusted-resource allowlist |
| 40 | `tools/vol2_tools.py` | Volatility 2 wrapper |
| 41 | `tools/vol3_tools.py` | Volatility 3 wrapper |

### 1b. Configuration and tooling (25)

| # | path | role |
|---|---|---|
| 1 | `.gitattributes` | line-ending policy |
| 2 | `LICENSE` | licence |
| 3-8 | `benchmark_results/*.json` (6) | `all_cases_benchmark_summary`, `cfreds`, `encrypt_them_all`, `jean`, `nitroba`, `sysinternals` |
| 9 | `benchmarks/ground_truth_cases.json` | ground truth for benchmarks |
| 10 | `ground_truth_base_admin.json` | base ground truth |
| 11 | `install.sh` | installer (10.9 KB) |
| 12-13 | `logs/final_runs/memory_self_correction_*.json` (2) | execution log + report |
| 14-24 | `memory_debug/*.parsed.json` (11) | parsed Volatility output: cmdline, cmdscan, consoles, getsids, malfind, netscan, pslist, psscan, pstree, svcscan, timeliner |
| 25 | `requirements.txt` | **dependency pins - see section 5** |

### 1c. Documentation (19)

`ACCURACY_REPORT.md`, `ARCHITECTURE.md`, `BENCHMARK_MATRIX.md`, `DATASET.md`,
`JUDGE_READINESS_CHECKLIST.md`, `PROJECT_DESCRIPTION.md`, `benchmark_results/README.md`,
`benchmarks/README.md`, `logs/README.md`, `logs/final_runs/memory_self_correction_report.md`,
and the 9 `skills/*.md` playbooks: credential-dumping, indicators-of-compromise,
lateral-movement, living-off-the-land, memory-forensics, mitre-attack-mapping, persistence,
process-injection, rootkit-detection.

### 1d. Binary asset (1)

`architecture.png` (533,340 bytes) - the original README's architecture figure.

---

## 2. The two conflicting files, exactly

### Conflict 1: `.gitignore`

**Side A - original PHANTOM DFIR (`3005762`)**, 8 rules, 88 bytes:

```
base-admin-memory.img
__pycache__/
*.pyc
*.bak
*.router_backup_
*.E01
*.img
*.raw
```

**Side B - AI module (`8017d1a`)**, 23 rules:

```
__pycache__/
*.py[cod]
.pytest_cache/
.venv/
venv/
*.egg-info/
.ipynb_checkpoints/
# Rust builds
phantom-guard/target/
# Memory images for local integration testing. Never committed: a 2 GB image
# in git makes every clone miserable. Fetch with scripts/fetch_test_image.sh.
test-images/
*.raw
*.vmem
*.lime
# Trained adapters and evaluation scratch. A LoRA adapter is ~115 MB; committing it
# would bloat every clone for an artifact that is reproducible from data/train.jsonl
# in ~22 minutes on a 4060. Copy from the training box with scripts/pull_adapter.sh
# and evaluate locally. Keep the METRICS in git, not the weights.
artifacts/*-adapter/
artifacts/*.log
artifacts/.hf_token
*.safetensors
```

**Original implementation that MUST be preserved:** `base-admin-memory.img`, `*.bak`,
`*.router_backup_`, `*.E01`, `*.img`. Only `*.raw` and `__pycache__/` survive into side B.
So a "take theirs" resolution would start **committing forensic disk images** (`*.E01`,
`*.img`) and router backups. These are evidence files and multi-GB images; committing them
would bloat the repo and risk leaking case data. **Side A's rules are the ones that protect
the original project and are non-negotiable.**

**Decision: union.** Both rule sets, side A's preserved verbatim.

### Conflict 2: `README.md`

**Side A (original):** 19,440 chars, 34 `##` sections, **3 screenshots**, title
`# PHANTOM DFIR`, subtitle "Parallel Hypothesis Analysis with Multi-agent Threat Hunting
Overlay Network". Content: Core Innovation, both install paths (SANS SIFT and WSL), Steps
1-9, Volatility 2 wrapper, disk/E01/PCAP analysis, unified router, multi-case benchmark
commands, output files, architecture, file structure, v2.1 and v2.0 improvement tables.

**Side B (AI module):** 15,025 chars, 12 `##` sections, **0 screenshots**, title
`# phantom-safety`. Content: headline metrics table, the finding, the repair, injection
scanner, Rust guard, layout, running it, reproducibility note, status, docs, licensing.

They are **not two versions of one document** - one is the product's usage guide, the other
is a research writeup about a safety layer. Overlap in content: near zero.

**Original implementation that MUST be preserved:** the PHANTOM DFIR title, the 3
screenshots, both install paths, Steps 1-9, and the improvement tables. These are the
project's front door and its install instructions; losing them is what the AI-side README
already did on the remote.

**Decision:** original as the source of truth, byte-for-byte as a prefix, with side B's
safety writeup appended below as additional sections. Verified: original head is a literal
prefix of the merged file, footer preserved verbatim, 3 screenshots retained.

---

## 3. AI Red Teaming components safe to integrate

All 113 AI-side paths are additive (no path collision with the engine). Grouped by
component, with integration classification:

### 3a. Add as-is - pure new modules (no contact with engine code)

| component | files | what it is |
|---|---|---|
| `phantom_ai_safety/harness/` | 2 | run upstream code with tool stubs and an injectable LLM |
| `phantom_ai_safety/red_team/` | 4 | row schema, evaluation families, injection attacks |
| `phantom_ai_safety/evaluation/` | 4 | metrics, baseline runner, before/after comparison |
| `phantom_ai_safety/grounding/` | 2 | the repaired verifier |
| `phantom_ai_safety/evidence_scanner/` | 4 | 27-rule injection scanner + normalisation + guard bridge |
| `phantom_ai_safety/repair/` | 4 | dataset build, QLoRA training, model eval |
| `phantom_ai_safety/curation/` | 2 | curation guards |
| `phantom-guard/` | 5 | the scanner reimplemented in Rust |
| `dashboard/` | 2 | AI safety dashboard |
| `data/` | 3 | train / heldout / manifest for the fine-tune |
| `results/` | 7 | stored result JSON, all figures derived from these |
| `tests/` | 6 | pytest suite for the module |
| `articles/` | 1 | HF writeup |
| `artifacts/torch-install.log.err` | 1 | install log |

### 3b. Add, but they EXECUTE the engine (read-only coupling - verify no writes)

| component | files | coupling |
|---|---|---|
| `scripts/` | 46 | harness scripts that import and run the engine under stubs. Includes `smoke_harness.py`, `run_red_team.py`, `verify_report_claims.py`, and GPU/adapter tooling (`gpu_*.sh`, `pull_adapter.sh`, `run_adapter_eval.sh`). |
| `docs/` | 19 | the module's own docs + 5 figure PNGs |

**The critical boundary:** `docs/EXISTING_ARCHITECTURE.md` and
`docs/RED-TEAM-ARCHITECTURE.md` document how the module consumes the engine. The module's
own README states the upstream clone is "imported and measured **unmodified**; nothing in
this repository edits it." That claim is consistent with the file evidence: no AI-side file
is a modified copy of any engine file. **Coupling is import-and-observe, not modification.**

### 3c. Components that need the engine present (and now have it)

`phantom_ai_safety/harness/env.py`, `scripts/smoke_harness.py`, `scripts/run_red_team.py`,
and `phantom_ai_safety/evaluation/*` require `PHANTOM_ROOT` to point at the engine. In the
original split these were run against a *separate* clone. After integration they resolve to
the engine inside the same repo, which is strictly better: one tree, one version.

---

## 4. Recommended base commit

**`3005762`** - Romil's tip ("Simplify README architecture diagram").

Rationale: it is the complete platform (88 files, 31 Python, all capability dirs, internally
consistent, 31/31 parse, all 5 internal packages resolve). The AI-side tip is a complete
*module* but an incomplete *platform*. Basing on `3005762` keeps the forensic engine as the
primary application, which is the stated requirement.

---

## 5. Dependency mismatches (analysis only - nothing modified)

### 5a. `requirements.txt` is incomplete in the original

Actual imports across the integrated tree vs the pins in `requirements.txt`:

| package | imported by | in `requirements.txt`? |
|---|---|---|
| `Evtx` | `disk_correlator.py` (3 call sites: lines 15199, 15597, 15972) | **NO - MISSING** |
| `langchain_anthropic` | `tools/llm_provider.py` | **NO - MISSING** |
| `langchain_groq` | `tools/llm_provider.py` | **NO - MISSING** |
| `langchain_openai` | `tools/llm_provider.py` | **NO - MISSING** |
| `langgraph` | agents | yes |
| `langchain_core` | agents | yes |
| `langchain_ollama` | agents | yes |
| `volatility3` | memory tools | yes |
| `fastapi`, `uvicorn`, `mcp` | `mcpserver/` | yes |
| `pyAesCrypt` | disk correlator | yes |
| `pefile` | artifact parsing | yes |

**Impact:** a clean `pip install -r requirements.txt` produces a tree where
`disk_correlator.py` raises `ImportError` on EVTX parsing, and `tools/llm_provider.py`
cannot construct the Anthropic, Groq, or OpenAI providers. Disk correlation and multi-LLM
routing - both advertised in the README - do not run.

Note `volatility3` is pinned but external DFIR tools (Sleuth Kit, tshark, ClamAV, libbde,
dislocker, gpg, Volatility symbols) are OS packages by design; the file says so. Not a bug.

### 5b. Proposed corrected `requirements.txt` (NOT applied)

```diff
 # Agent / LLM orchestration
 langgraph>=0.2.0
 langchain-core>=0.2.0
 langchain-ollama>=0.1.0
+langchain-anthropic>=0.1.0
+langchain-groq>=0.1.0
+langchain-openai>=0.1.0
 
 # Memory forensics
 volatility3>=2.7.0
 
 # MCP / HTTP server
 fastapi>=0.100.0
 uvicorn>=0.20.0
 mcp>=1.0.0
 
 # Artifact parsing and triage helpers
 pefile>=2023.2.7
 pyAesCrypt>=6.1.1
+
+# Windows Event Log parsing (disk_correlator.py imports Evtx.Evtx)
+python-evtx>=0.7.4
```

`Evtx` is the import name; the PyPI distribution is **`python-evtx`**.

### 5c. Other dependency observations

- The AI module adds its own Rust build (`phantom-guard/Cargo.toml`), separate from Python.
- `data/train.jsonl` + `heldout.jsonl` feed the fine-tune; the QLoRA path needs torch, which
  is deliberately kept out of `requirements.txt` (the module installs ML deps via
  `scripts/install_ml_deps.sh`). Two dependency tiers is intentional, not a mismatch.

---

## 6. Backups and destructive-operation status

**Confirmed untouched:**

| item | value | verification |
|---|---|---|
| `backup-before-recovery` branch | `25d3c758d5ffef3ba18dcbd12ce641094b6db908` | `git rev-parse` |
| `phantom-backup.bundle` | 3,588,216 bytes, LastWriteTime 2026-11-12 10:02:16 | `Get-Item` + `git bundle verify` -> 6 refs |

**Confirmed no destructive operation:**

- No merge: `git rev-parse MERGE_HEAD` -> *unknown revision* (no merge in progress)
- No cherry-pick, no rebase, no reset: branch tip is unchanged at `25d3c75`
- No file deleted: every file present in `3005762` is present in the working tree
- Branch list unchanged: `backup-before-recovery`, `integrated/ai-safety`, `master`

---

## 7. Phased integration plan (NOT started - awaiting approval)

### Phase 1: Files to ADD (113, no engine file touched)

```
phantom_ai_safety/          23 files   harness, red_team, evaluation, grounding,
                                       evidence_scanner, repair, curation
phantom-guard/               5 files   Rust scanner (Cargo.toml, Cargo.lock, src/)
scripts/                    46 files   harness + probes + GPU/adapter tooling
docs/                       19 files   module docs + docs/img/ figures
results/                     7 files   stored metrics (all README figures derive from these)
tests/                       6 files   module pytest suite
data/                        3 files   train.jsonl, heldout.jsonl, MANIFEST.json
dashboard/                   2 files   safety dashboard
articles/                    1 file    HF writeup
artifacts/                   1 file    torch install log
```

### Phase 2: Files to MODIFY (2 only)

| file | change | direction |
|---|---|---|
| `.gitignore` | union: side A's 8 rules preserved verbatim + side B's rules appended | original rules are primary |
| `README.md` | original as byte-exact prefix + 3 screenshots + safety writeup appended below | original is primary |

### Phase 3: Files that MUST REMAIN UNTOUCHED (all 88 original files)

Byte-identical, verified by blob SHA. The 86 non-conflicting originals plus the original
content of the 2 modified files. Specifically:

- `disk_correlator.py` (1.18 MB), `phantom_router.py`, `forensic_reasoning_patch.py`
- all of `agents/` (7), `correlation/` (9), `tools/` (9), `skills/` (9), `mcpserver/` (1)
- `main.py`, `config.py`, `state.py`, `benchmark.py`, `benchmark_reports.py`, `test_mcp.py`
- `install.sh`, `requirements.txt`, `LICENSE`, `.gitattributes`
- all of `benchmarks/`, `benchmark_results/`, `logs/`, `memory_debug/`
- all 19 original documentation files and `architecture.png`

### Phase 4: Conflict resolution decisions

1. `.gitignore` -> **union**, side A primary. Rejected: "take theirs" (would commit
   `*.E01`/`*.img` forensic images); "take ours" (would commit the AI module's 2 GB
   `test-images/` and 115 MB adapter artifacts).
2. `README.md` -> **original prefix + appended safety sections**. Rejected: taking side B
   (loses the 3 screenshots and the entire install guide); a paragraph-level interleave
   (the documents share almost no content, so interleaving produces incoherence).

### Phase 5: Regression testing strategy

Ordered, cheapest first, and each result recorded:

1. **Parse gate** - every `.py` in the integrated tree parses under `utf-8-sig`.
   Already passing: 89/89.
2. **Engine identity gate** - per-file blob SHA of all 88 originals vs `3005762`.
   Already passing: 86/88 identical, the 2 differences being the intended conflicts.
3. **Import gate** - engine packages import in isolation (`agents`, `config`,
   `correlation`, `state`, `tools`). Already passing: 5/5.
4. **Engine test gate** - `python test_mcp.py`. **NOT YET RUN.**
5. **Module test gate** - `pytest tests/ -q` on the AI suite (6 files).
   **NOT YET RUN** - venv + pytest being installed.
6. **Functional gate** - injection scanner on benign / plain / base64 input.
   Already passing: 0/1/1 findings.
7. **Claims gate** - `python scripts/verify_report_claims.py`, which fails the build if a
   README figure stops matching a stored result. **NOT YET RUN.**
8. **Boot gate** - `python scripts/smoke_harness.py` and `scripts/validate_scanner.py`.
   **NOT YET RUN.**

Gates 1, 2, 3, 6 pass. Gates 4, 5, 7, 8 are open and are the acceptance criteria before
anything lands.

### Phase 6: Landing

1. Push `integrated/ai-safety` as a **branch**, never to `main`.
2. Open a PR with Romil as reviewer; base `main` = his `3005762`.
3. After approval, fast-forward `main`.
4. Separately, fix `requirements.txt` (section 5b) - arguably its own commit, since it is a
   pre-existing engine bug independent of the integration.

### Explicitly rejected approaches

- Merging root `1219666` into Romil's history (unrelated roots; duplicates ~88 files)
- Cherry-picking the 26 AI commits (they assume their own layout; conflicts on every path)
- Force-pushing `main` in either direction (this is what caused the split)
- Rebasing either history

---

## 8. Status summary

| item | state |
|---|---|
| Original engine | complete and intact in `3005762` and in the local clone |
| AI module | intact at `8017d1a` / `25d3c75` |
| Integration commit | `2fa27b6` exists (parent `3005762`, 0 deletions) but this audit is not an approval to land it |
| Conflicts | 2, both decided, both non-code |
| Dependency fix | analysed, **not applied** |
| Backups | untouched |
| Destructive ops | none |
| Open acceptance gates | 4 (engine test, module pytest, claims verifier, smoke harness) |