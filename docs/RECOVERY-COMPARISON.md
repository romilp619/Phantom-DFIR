# PHANTOM DFIR — GitHub History Comparison and Recovery Recommendation

Repo: https://github.com/romilp619/Phantom-DFIR
Prepared: 2026-11-12 10:05 America/Chicago
Scope: read-only inspection. Nothing restored, modified, or pushed in this document.

Backups taken first, as instructed (in `redirect\phantom-safety`):

```
git branch backup-before-recovery        -> 25d3c75
git bundle create phantom-backup.bundle --all
```

Bundle verified readable: 3,588,216 bytes, 6 refs.

---

## 0. Correction to the premise

The brief states: "KitsuneTech: 3005762 -> 48d2de0" as a force-push event.

**That is not what happened.** Verified two ways:

| check | result |
|---|---|
| `git rev-parse 48d2de0^` | `66fb263` — NOT `3005762` |
| `git merge-base --is-ancestor 3005762 48d2de0` | **NO** (unrelated) |
| root of `48d2de0` | `1219666` |
| root of `3005762` | `700c4c4` |

`48d2de0` descends from `1219666`. `3005762` descends from `700c4c4`. These are **two
unrelated commit graphs**, not one branch rewritten over another. `48d2de0` never had
`3005762` as its parent, so `3005762 -> 48d2de0` was not a force-push edge.

The "8 subsequent commits, 48d2de0 -> 8017d1a" part **is** correct: `git rev-list --count
48d2de0..8017d1a` = 8.

What actually happened is simpler and worse for the repo: two independent repositories were
created and **both pushed to the same remote `main`**, the second one (the AI side, on its own
root) ending up as the remote's current state. The remote `main` therefore does not merely
lack Romil's work — it shares no history with it at all.

- Romil's branch: 35 commits, `700c4c4` -> `3005762`, May 14 - Jun 15.
- AI branch: 26 commits, `1219666` -> `8017d1a`, Nov 10 - Nov 12.
- `origin/main` = `8017d1a`, and **`3005762` is not an ancestor of it**.

---

## 1. Every deleted / renamed / overwritten / substantially modified file

`git diff --name-status 3005762 8017d1a` — 201 entries total:

| status | count | meaning |
|---|---|---|
| **D** deleted (in Romil's tree, absent from remote) | **86** | the entire forensic engine |
| **A** added (only in remote) | **113** | the AI safety module |
| **M** modified | **2** | `.gitignore`, `README.md` |

There are no renames in the git sense: because the two trees share no history, git reports
every file on the vanishing side as a delete and every file on the appearing side as an add.

### 1a. The 86 files absent from `8017d1a`

`.gitattributes`, `ACCURACY_REPORT.md`, `ARCHITECTURE.md`, `BENCHMARK_MATRIX.md`,
`DATASET.md`, `JUDGE_READINESS_CHECKLIST.md`, `LICENSE`, `PROJECT_DESCRIPTION.md`,
`agents/__init__.py`, `agents/collector.py`, `agents/evidence.py`, `agents/investigator.py`,
`agents/orchestrator.py`, `agents/reporter.py`, `agents/skeptic.py`, `architecture.png`,
`benchmark.py`, `benchmark_reports.py`, `benchmark_results/README.md`,
`benchmark_results/all_cases_benchmark_summary.json`,
`benchmark_results/cfreds_benchmark_result.json`,
`benchmark_results/encrypt_them_all_benchmark_result.json`,
`benchmark_results/jean_benchmark_result.json`, `benchmark_results/nitroba_benchmark_result.json`,
`benchmark_results/sysinternals_benchmark_result.json`, `benchmarks/README.md`,
`benchmarks/ground_truth_cases.json`, `config.py`, `correlation/__init__.py`,
`correlation/__pycache__/*.pyc` (4), `correlation/confidence.py`, `correlation/mitre.py`,
`correlation/mitre_rules.py`, `correlation/timeline.py`, `disk_correlator.py`,
`forensic_reasoning_patch.py`, `ground_truth_base_admin.json`, `install.sh`, `logs/*`,
`main.py`, `memory_debug/*`, `phantom_router.py`, `requirements.txt`, `skills/*`,
`state.py`, `test_mcp.py`, `tools/*` (`vol3_tools.py`, `vol2_tools.py`, `memory_triage.py`,
`legitimacy_engine.py`, `trusted_resources.py`, `skills_loader.py`, `accuracy.py`,
`llm_provider.py`), and the remaining top-level docs.

Full machine-readable list:
`git -C <repo> diff --name-status 3005762 8017d1a`

### 1b. The 2 modified files

| file | change |
|---|---|
| `README.md` | replaced. Original title `# PHANTOM DFIR`; remote title `# phantom-safety`. The three screenshot references were removed. |
| `.gitignore` | different rule set (Romil's vs the AI module's) |

---

## 2. Original forensic architecture vs current (remote) architecture

**Romil's tree (the original platform).** A multi-agent DFIR pipeline over Volatility 2 and 3
plus disk and network artifact sources:

```
Volatility 2 + 3 wrappers        tools/vol2_tools.py, tools/vol3_tools.py
Memory triage                    tools/memory_triage.py
Disk / E01 / PCAP correlation    disk_correlator.py, forensic_reasoning_patch.py
Evidence + legitimacy scoring    tools/legitimacy_engine.py, tools/trusted_resources.py
Skills + routing                 tools/skills_loader.py, phantom_router.py
Agents (argue/verify)            agents/{orchestrator,investigator,collector,evidence,reporter,skeptic}.py
Correlation + threat scoring     correlation/{confidence,mitre,mitre_rules,timeline}.py
Benchmarks + ground truth        benchmark.py, benchmarks/, benchmark_results/
Entry / config / state           main.py, config.py, state.py, install.sh, mcpserver/
Docs + judge pack                ARCHITECTURE.md, ACCURACY_REPORT.md, BENCHMARK_MATRIX.md,
                                 DATASET.md, JUDGE_READINESS_CHECKLIST.md, PROJECT_DESCRIPTION.md
```

**Remote tree (`8017d1a`).** A different application that consumes DFIR *output*:

```
phantom_ai_safety/harness/            run upstream code with tool stubs, injectable LLM
phantom_ai_safety/red_team/           row schema, 7 evaluation families, injection attacks
phantom_ai_safety/evaluation/         metrics, baseline runner, before/after comparison
phantom_ai_safety/grounding/          repaired verifier (replaces upstream confidence policy)
phantom_ai_safety/evidence_scanner/   27-rule prompt-injection scanner + normalisation
phantom_ai_safety/repair/             dataset build, QLoRA train, model eval
phantom-guard/                        the scanner reimplemented in Rust
dashboard/, docs/, scripts/, tests/, results/, data/, articles/
```

The two architectures are **complementary, not competing**: the remote tree's own README says
it is "an additive safety layer over PHANTOM DFIR" whose upstream clone is "imported and
measured unmodified". It expects Romil's engine to exist. It simply was never merged into it.

---

## 3. Capability verification

Checked with `git cat-file -e <ref>:<path>` per file, 25 representative capability files:

| area | files checked | in Romil's tree | in remote `8017d1a` |
|---|---|---|---|
| Memory forensics (Vol2/Vol3/triage) | 3 | 3 | **0** |
| Disk forensics | 2 | 2 | **0** |
| IOC / threat-intel / routing | 4 | 4 | **0** |
| Correlation / threat scoring | 4 | 4 | **0** |
| Agents | 6 | 6 | **0** |
| Benchmarks | 3 | 3 | **0** |
| Reporting / entry / config | 4 | 3 | **0** |

**Files present in both trees: 2** (`.gitignore` and `README.md` only). Every one of the 25
capability files is intact in Romil's tree and absent from the remote tip. Nothing was
refactored or renamed in the remote — it is simply a different codebase.

**Are those capabilities intact locally?** Yes. In `redirect\Phantom-DFIR` (branch `main` at
`3005762`) all of it is present on disk and tracked: 88 files, no deletions, and the working
tree is clean against `3005762`. Every original `.py` file parses (89/89 with `utf-8-sig`).
Four files (`agents/investigator.py`, `agents/orchestrator.py`, `agents/reporter.py`,
`state.py`) carry a UTF-8 BOM; that is pre-existing in Romil's commits, byte-identical to his,
and not damage.

**Nothing was destroyed.** The 86 files are absent from one branch, but fully present and
intact in Romil's history and in the local clone.

---

## 4. Extensions or replacements?

**Both, depending on which branch you look at — which is the whole problem.**

- On the **AI branch itself**, the work is genuinely **additive**: it adds
  `phantom_ai_safety/`, `phantom-guard/`, `dashboard/`, `docs/`, `scripts/`, `tests/` and
  touches no forensic file. Measured against Romil's tree, 113 of its 115 files are new
  paths; only `.gitignore` and `README.md` overlap.
- On **`origin/main`**, the result is a **replacement**, because the AI branch has an
  unrelated root. Pushing it made the remote's `main` a tree that does not contain the
  forensic engine at all.

So the teammate's characterisation is right about the *effect* on `main` and wrong about the
*mechanism* (no force-push edge from `3005762`; two unrelated roots). The AI work was not
written as a replacement — it was published in a way that displaced the engine.

**The GPU tooling** (`scripts/gpu_*.sh`, `scripts/run_adapter_eval.sh`,
`scripts/pull_adapter.sh`, `phantom_ai_safety/repair/train_qlora.py`, adapter artifacts) is
**purely additive** — new scripts and a training path, no forensic file touched.

---

## 5. Recovery recommendation

The direction is fixed and correct: **Romil's PHANTOM DFIR stays the base and primary
project; the AI Red Teaming / Safety work is integrated into it as additional modules.**

This is already built and does not need a second recovery. In `redirect\phantom-safety`:

```
25d3c75  results: stored adapter eval (40 rows) and rule baseline (550 rows)   [AI]
2fa27b6  Integrate AI Red Teaming and Safety module into PHANTOM DFIR         [RECOVERY]
3005762  Simplify README architecture diagram                                 [romil]
```

`2fa27b6`'s parent is `3005762`, so Romil's engine is the base. Verified:

- `git diff --stat 3005762 2fa27b6` -> **115 files changed, 56080 insertions(+), 0 deletions**
- Romil's files missing from `2fa27b6`: **0**
- 86 of Romil's 88 files are **bit-identical** (same blob SHA); only `.gitignore` and
  `README.md` differ, both deliberately, both additive in content.
- `.gitignore` is a **union** — all 8 of Romil's ignore rules retained.
- `README.md` keeps the original as a byte-exact prefix with all 3 screenshots, safety writeup
  appended below.
- Functional check: injection scanner returns 0 findings on a benign forensic line, 1 on a
  plain injection, 1 on nested base64; `state`, `config`, `correlation.confidence` import
  alongside it.
- 201/201 tracked files present on disk; the 2 GB memory image, adapter, and gitignored dirs
  untouched.

### Conflict set (the honest answer to "show me conflicting files before merging")

**Two files.** `.gitignore` and `README.md`. Both already resolved as above. There are no
other conflicts, because the module adds new directories and edits no forensic source.

### Recommended order of operations

1. Keep `backup-before-recovery` and `phantom-backup.bundle` (done).
2. Review `2fa27b6` locally: `git diff 3005762 2fa27b6 --stat`.
3. Push **`integrated/ai-safety` as a branch**, not to `main`. Do not force-push `main`.
4. Open a PR titled as an integration, with Romil as reviewer, so the base-vs-module
   direction is visible in the diff.
5. Only after Romil approves, fast-forward `main` to the integrated commit.
6. Install pytest in a venv and run both suites as the regression gate. This has **not** been
   run: there is no pytest on this machine.
7. Optionally follow up with the spec's Phase 6 docs (`PROJECT_AUDIT.md`, `SAFETY_DESIGN.md`,
   `EVALUATION.md`, `LIMITATIONS.md`).

### What is NOT recommended

- Force-pushing `main` in either direction. That is what created this situation.
- Merging the AI branch's root into Romil's history. It would duplicate the whole tree; the
  additive integration in `2fa27b6` is the clean form.
- Rewriting either branch's history.

---

## 6. Status

| item | state |
|---|---|
| Romil's original engine | intact, local `Phantom-DFIR` @ `3005762`, 88 files, clean tree |
| AI module source | intact, `phantom-safety` @ `25d3c75` |
| Integration | built at `2fa27b6`, 0 deletions, on branch `integrated/ai-safety` |
| Backups | `backup-before-recovery`, `phantom-backup.bundle` (3.6 MB, verified) |
| Pushed | **nothing** |
| Regression tests | **not run** — no pytest installed |