# PHANTOM DFIR — Judge Readiness Checklist

This checklist maps PHANTOM DFIR to the Find Evil judging requirements from the
judge pack and quick-reference PDFs.

## Stage One Submission Requirements

| Requirement | Status | Evidence in Repository | Remaining Action |
|---|---:|---|---|
| Public repository | Ready if GitHub repo is public | `https://github.com/romilp619/Phantom-DFIR` | Confirm repo visibility on GitHub before submission |
| MIT or Apache 2.0 license | Ready | `LICENSE` | Confirm GitHub About panel detects the license |
| README with setup/run instructions | Ready | `README.md` | None |
| Demo video under 5 minutes | Missing from repo | Devpost/video link, not a repo file | Record/upload final demo video |
| Architecture diagram | Ready | `architecture.png`, `ARCHITECTURE.md` | Confirm Devpost gallery includes it |
| Text project description | Ready | `PROJECT_DESCRIPTION.md` | Copy polished summary into Devpost |
| Evidence dataset documentation | Ready | `DATASET.md`, `benchmarks/ground_truth_cases.json`, `BENCHMARK_MATRIX.md` | None |
| Accuracy report | Ready, can be stronger | `ACCURACY_REPORT.md`, `benchmark.py`, `benchmark_reports.py` | Add final benchmark output JSONs after final runs |
| Try-it-out instructions | Ready | `README.md`, `install.sh`, `test_mcp.py` | None |
| Agent execution logs | Partial | `memory_debug/*.json`, PHANTOM generated reports, router unified JSONs | Add final `logs/` directory with selected run logs and trace JSONs |

## Three Required Capabilities

| Capability | Status | Evidence |
|---|---:|---|
| Self-correction without human intervention | Partial to Ready | Memory self-correction in `main.py` / agents, router evidence gap controller in `phantom_router.py` |
| Accuracy validation traceable to artifacts/files/log entries | Ready | `benchmark_reports.py`, `benchmarks/ground_truth_cases.json`, `BENCHMARK_MATRIX.md` |
| Structured investigative narrative, not raw execution log | Ready | JSON/Markdown reports from `disk_correlator.py` and unified reports from `phantom_router.py` |

## Six Judging Criteria

### 1. Autonomous Execution Quality

Status: Strong, but final logs must prove it.

Evidence:

- `agents/orchestrator.py`
- `agents/skeptic.py`
- `phantom_router.py`
- router `evidence_gap_controller` output in unified JSON

Need for submission:

- Include one or two final router logs showing:
  - initial confidence
  - detected gaps
  - action/rerun decision
  - final confidence

### 2. IR Accuracy

Status: Strong.

Evidence:

- `ground_truth_base_admin.json`
- `benchmarks/ground_truth_cases.json`
- `benchmark.py`
- `benchmark_reports.py`
- `ACCURACY_REPORT.md`
- `BENCHMARK_MATRIX.md`

Need for submission:

- Save final benchmark outputs into `logs/` or `benchmark_results/`.

### 3. Breadth and Depth

Status: Strong.

Evidence types covered:

- Memory
- Disk / E01 / raw
- PCAP
- Outlook/PST
- Browser/WebCache
- Registry
- Prefetch
- Amcache/BAM/SRUM
- Event logs
- Web logs/webshell artifacts
- Malware triage
- Crypto recovery
- Attribution graphing

### 4. Constraint Implementation

Status: Strong.

Evidence:

- `ARCHITECTURE.md`
- `mcpserver/mcp_server.py`
- `ACCURACY_REPORT.md`

Key story:

- MCP exposes typed tools, not arbitrary shell execution.
- Evidence is hashed and processed read-only.
- Iteration caps prevent infinite loops.
- Prompt guardrails are backed by static validation/fallbacks.

### 5. Audit Trail Quality

Status: Partial until final logs are checked in.

Current evidence:

- `memory_debug/*.json`
- generated PHANTOM reports in local runs
- unified router JSONs contain `source_reports`, `llm_status`, `unified_analysis`,
  and `evidence_gap_controller`

Need for submission:

- Add final logs for at least three traceable claims:
  - one memory claim
  - one disk claim
  - one PCAP claim

Suggested final directory:

```text
logs/
├── base_admin_memory_run.log
├── sysinternals_run.log
├── nitroba_router_run.log
├── nitroba_unified.json
├── m57_jean_report.json
└── benchmark_results.json
```

### 6. Usability and Documentation

Status: Ready.

Evidence:

- `README.md`
- `install.sh`
- `test_mcp.py`
- `DATASET.md`
- `ARCHITECTURE.md`
- `PROJECT_DESCRIPTION.md`

## Three-Claim Trace Examples for Judges

Use these in the demo or final report package.

| Claim | Supporting Output | Ground Truth / Validator |
|---|---|---|
| Nitroba actor is `jcoachj@gmail.com` | PHANTOM network attribution report / unified JSON | `benchmark_reports.py --case nitroba_harassment_pcap` |
| M57 Jean disclosed `m57biz.xls` to `tuckgorge@gmail.com` | PHANTOM Outlook/phishing report | `benchmark_reports.py --case m57_jean_phishing` |
| SysInternals chain includes VMToolsIO, Defender, SRUM/BAM/USN/Prefetch | PHANTOM SysInternals report | `benchmark_reports.py --case sysinternals_case` |

## Final Pre-Submission Commands

Run syntax checks:

```bash
python3 -m py_compile main.py disk_correlator.py phantom_router.py benchmark_reports.py
```

Run MCP smoke test:

```bash
python3 mcpserver/mcp_server.py --transport http --host 127.0.0.1 --port 8765
python3 test_mcp.py --memory /path/to/memory.img
```

Run one report benchmark:

```bash
python3 benchmark_reports.py \
  --case nitroba_harassment_pcap \
  --report /home/romil/phantom_unified_pcap_nitroba.pcap_20260612_174103.json
```

Run all final report benchmarks with exact report paths when possible:

```bash
python3 benchmark_reports.py --all --reports-dir /home/romil --latest \
  --output /home/romil/phantom_multi_case_benchmark.json
```

## Highest-Priority Remaining Work

1. Record the final demo video.
2. Add final execution logs / trace JSONs to a `logs/` or `benchmark_results/`
   folder.
3. Run the benchmark framework against final report paths.
4. Confirm GitHub repo is public and license is detected in the GitHub About
   sidebar.
5. Confirm the Devpost page includes the architecture diagram and demo video.
