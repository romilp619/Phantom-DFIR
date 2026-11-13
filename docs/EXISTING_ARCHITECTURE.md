# EXISTING_ARCHITECTURE.md — PHANTOM DFIR

Structural map of the public upstream clone at `Phantom-DFIR/`. Every claim carries a file:line or a function name. Verified 2026-11-10.

## 1. Entry points

| File | Lines | Role |
|---|---:|---|
| `main.py` | 148 | Memory-image entry point. `--file/-f`, `--model`, `--ollama-url`, `--provider`, `--api-key`, `--no-llm`, `--deep`, `--self-correct`. Overrides `config` globals at `:91-96` then calls `run_investigation`. |
| `phantom_router.py` | 427 | Router that dispatches to the memory pipeline or the disk pipeline and emits a unified JSON with `source_reports`, `llm_status`, `unified_analysis`, `evidence_gap_controller`. |
| `disk_correlator.py` | 20713 | Separate disk / E01 / PCAP / PST pipeline. Not a library for the memory path; it is a parallel application. |
| `benchmark.py` | 243 | Scores a memory run against a ground-truth JSON. |
| `benchmark_reports.py` | 274 | Scores saved report JSONs by alias containment. |
| `mcpserver/mcp_server.py` | 733 | MCP server over typed read-only tools. |

The real top-level for a memory investigation is `main.py` -> `agents.orchestrator.run_investigation` (`agents/orchestrator.py:248`).

## 2. Agent pipeline

A LangGraph `StateGraph` built in `agents/orchestrator.py:30` (`build_graph`), with a skip-collector variant at `:405`.

Node order:

1. **collector** — `agents/collector.py:276` `run_collector`. Engine detection (`:21`), OS detection (`:30`), parallel plugin execution (`:242` `_run_parallel`, 16 workers).
2. **investigator** — `agents/investigator.py:490` `run_investigator`. LLM hypothesis generation plus a deterministic baseline (`:635` `_static_fallback`). Category extractors at `:263` C2, `:305` SSH targets, `:341` suspicious services.
3. **evidence** — `agents/evidence.py:191` `run_evidence_agent`. Targeted re-query via `gather_targeted_evidence` (`:45`) and `check_evidence_confirms` (`:135`). **Sole writer of `verified_sources` at `:227`.**
4. **skeptic** — `agents/skeptic.py:134` `run_skeptic`. Verdict assignment and confidence bucketing.
5. **conditional edge** — `agents/skeptic.py:249` `should_continue_debate` returns `"evidence"` to loop or `"reporter"` to finish.
6. **reporter** — `agents/reporter.py:404` `run_reporter`.

Shared state: `state.py`, an `InvestigationState` TypedDict with fields including `hypotheses`, `verified_sources`, `critical_findings`, `medium_findings`, `low_findings`, `cleared_findings` (`:55`), `skeptic_round`, `reasoning_log`.

Loop bound: `config.py:42` `MAX_SKEPTIC_ROUNDS = 3`, gated additionally by `skeptic.py:259-265`, which only re-queries `UNVERIFIED`/`LOW` hypotheses below three sources.

## 3. Verification layer (the subject under test)

- `correlation/confidence.py:39` `score(verified_sources, hypothesis)`:
  - `:44` deduplicates with `len(set(verified_sources))`.
  - `:47-48` returns `CLEARED` if `is_benign_hypothesis` matches claim text.
  - `:50-57` thresholds to CRITICAL / MEDIUM / LOW / UNVERIFIED.
- `correlation/confidence.py:18-25` `BENIGN_INDICATORS`, a substring list including `"benign"` and `"not malicious"`.
- `correlation/confidence.py:28` `is_benign_hypothesis`, substring match on claim text.
- Thresholds: `config.py:43-44` `MIN_SOURCES_CRITICAL = 3`, `MIN_SOURCES_MEDIUM = 2`.
- `agents/skeptic.py:113` `_enforce_evidence_rules`, the hard override.
- `agents/skeptic.py:81` `_rule_based_skeptic`, the identical no-LLM mapping.

## 4. Tool layer

| Module | Lines | Exposes |
|---|---:|---|
| `tools/vol3_tools.py` | 349 | 40+ Windows plugins plus a large Linux plugin block (`linux_netfilter:229` through `linux_vma_regexscan:351`) and detectors `detect_dkom:368`, `detect_module_stomping:400`, `detect_unhooking:438`. |
| `tools/vol2_tools.py` | 94 | 18 legacy plugins (`pslist:82`, `hashdump:71`, `malfind:91`, `netscan:100`, and others) with profile detection at `:17`. |
| `tools/memory_triage.py` | 319 | Fast triage wrapper. |
| `tools/legitimacy_engine.py` | 553 | Identity/behaviour scoring; CLEARED assignment at `:620-632`; exact-name masquerade exemption at `:362-363`. |
| `tools/trusted_resources.py` | 278 | Benign-path and vendor allowlists. |
| `tools/skills_loader.py` | 106 | Phase-scoped prompt context. |
| `tools/llm_provider.py` | 123 | Provider factory (`ollama`, `claude`, `openai`, `groq`) at `create_llm:20`. |
| `tools/accuracy.py` | 113 | Dead code, no call sites. |

## 5. Correlation layer

- `correlation/confidence.py` (69 lines) — evidence-count to confidence mapping. Subject under test.
- `correlation/mitre.py` (151) plus `correlation/mitre_rules.py` (227) — ATT&CK technique mapping.
- `correlation/timeline.py` (211) — event ordering.

## 6. MCP server

`mcpserver/mcp_server.py` (733 lines). Exposes typed forensic tools over stdio and HTTP; `test_mcp.py` (108 lines) is the smoke test. The design intent is that destructive operations are absent from the tool surface rather than forbidden by prompt, which is a sound architectural choice.

## 7. Data and logs present in the repository

- `benchmark_results/` — 5 per-case JSONs plus `all_cases_benchmark_summary.json`.
- `benchmarks/ground_truth_cases.json` — 7 cases with weights and forbidden phrases.
- `ground_truth_base_admin.json` — 4 malicious, 4 benign, plus network and SSH target lists.
- `logs/` — case logs for CFReDS leakage, Ali Hadi, M57 Jean, Nitroba, SysInternals, plus memory self-correction JSON and Markdown.

Note: three mutually incompatible ground-truth formats exist across `benchmark.py:12-26`, `benchmarks/ground_truth_cases.json`, and `tools/accuracy.py:41`, with no schema version or hash.

## 8. Runtime dependencies

`requirements.txt`: `langgraph>=0.2.0`, `langchain-core>=0.2.0`, `langchain-ollama>=0.1.0`, `volatility3>=2.7.0`, `fastapi>=0.100.0`, `uvicorn>=0.20.0`, `mcp>=1.0.0`, `pefile>=2023.2.7`, `pyAesCrypt>=6.1.1`.

External binaries resolved via `shutil.which` at `config.py:21-29`: `vol`, `vol2`, `log2timeline.py`, `mactime`, `mmls`, `fls`, `icat`, `strings`, `yara`. None are installed on this host.

## 9. Local runnability assessment

Cannot run here: the memory pipeline end to end (no Volatility, no image), the disk pipeline (no Sleuth Kit, no image), PCAP paths (no tshark), and the MCP smoke test against a real image.

Can run here: import and exercise the verification layer directly, because `correlation/confidence.py`, `agents/skeptic.py`'s override and rule paths, and `agents/evidence.py`'s accumulator are pure functions over text and structured objects. With `tools.vol3_tools` and `tools.vol2_tools` stubbed and the module-level `llm` neutralised, the real scoring code can be driven against synthetic evidence with no forensic tooling and no image present.

That is precisely the surface the red-team findings live on, so the experiment is fully executable on this host.