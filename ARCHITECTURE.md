# PHANTOM DFIR — Architecture

## System architecture

The current architecture diagram is maintained in **[README.md](README.md#architecture)**,
which is the single source of truth for it. It shows the evidence sources, the router, the
read-only tool layer, the MCP trust boundary, the three analysis engines, the evidence gap
controller and the output artifacts.

The three evidence paths are:

- **Memory** - `phantom_router.py` dispatches to `main.py`, where the LangGraph pipeline runs
  Collector, Investigator, Evidence agent, Skeptic and Reporter, with a bounded
  self-correction loop between the Skeptic and the Evidence agent.
- **Disk / E01 / raw** - dispatched to `disk_correlator.py` for filesystem, registry, browser,
  email, malware and crypto artifact analysis.
- **PCAP / PCAPNG** - also handled by `disk_correlator.py`, covering HTTP objects, webmail
  attribution and identity correlation.

The router can run a gap check over the reports each engine produces, rerun an engine where
evidence is thin, and gather the results into a unified report
(`--no-evidence-self-correct` disables this; `--gap-confidence` sets the target, default 0.85).

### Tool layer

| Module | Role |
|---|---|
| `tools/vol3_tools.py` | Volatility 3 wrappers - 40+ Windows and 30+ Linux plugins |
| `tools/vol2_tools.py` | Volatility 2 wrappers - auto-profile detection, `kdbgscan`, `hashdump` |
| `disk_correlator.py` | Memory-to-disk correlation, `log2timeline`, MFT parsing |
| `mcpserver/mcp_server.py` | 20 typed tools over stdio and HTTP, with SHA-256 verification |


## Architectural Pattern

**Multi-Agent Framework (LangGraph)** + **Custom MCP Server**

PHANTOM combines the two most valued approaches from the hackathon guidelines:

1. **LangGraph StateGraph**: 5 specialized agents communicate through a shared TypedDict state. No single model holds all raw data — evidence is distributed across plugin outputs and summarized before LLM context.

2. **Purpose-Built MCP Server**: 20 typed, read-only functions. The agent physically cannot run destructive commands because the server doesn't expose them.

## Trust Boundaries

| Boundary | Type | Enforcement |
|----------|------|-------------|
| No shell access via MCP | **Architectural** | Server exposes only 20 predefined functions |
| Evidence immutability | **Architectural** | SHA256 hash verified before every analysis |
| Read-only tool execution | **Architectural** | All subprocess calls use `capture_output=True`, no writes |
| Max iteration cap | **Architectural** | `MAX_SKEPTIC_ROUNDS = 3` hard-coded constant |
| IOC validation | **Prompt + Code** | `_is_valid_ioc()` rejects vague LLM outputs post-hoc |
| Investigator prompt schema | **Prompt** | If LLM ignores, static fallback guarantees baseline |

## Spoliation Testing

The MCP server was tested for evidence spoliation risk:

1. **No write tools exposed**: The MCP server has no `write_file`, `delete_file`, or `execute_command` tools
2. **SHA256 verification**: `register_evidence()` hashes the file at load; `verify_integrity()` re-hashes before analysis
3. **Subprocess isolation**: All Volatility calls use `subprocess.run()` with `capture_output=True` — stdout/stderr are captured, never piped to disk
4. **Failure mode**: If the model somehow requests a non-existent tool, the server returns `{"error": "Unknown tool"}` — no fallback to shell

**Result: Zero evidence spoliation risk through architectural enforcement.**

## The AI safety and red-team layer

This repository is the unified application: the forensic engine above, plus an AI safety and
red-team layer that attacks the agent's reasoning with adversarial evidence and measures
whether it can be pushed into a wrong verdict.

The integration is additive. The forensic engine was imported unmodified, which is the
layer's core methodological claim: a safety result measured against an edited system under
test proves nothing. `scripts/verify_integration_integrity.py` enforces this and reports
**86 of 88** original files byte-identical, with `.gitignore` and `README.md` the two declared
conflicts.

| Component | Role |
|---|---|
| `phantom_ai_safety/red_team/` | Adversarial evidence-injection attack generation and evaluation |
| `phantom_ai_safety/evidence_scanner/` | Prompt-injection scanner over forensic evidence, with a detection-normalisation pass |
| `phantom_ai_safety/grounding/` | Evidence-grounded verification of agent claims |
| `phantom_ai_safety/curation/` | Training-data curation guards |
| `phantom_ai_safety/evaluation/` | Baseline, comparison and metrics harness |
| `phantom_ai_safety/repair/` | QLoRA repair training and held-out evaluation |
| `phantom_ai_safety/harness/` | Evaluation environment wiring |
| `phantom-guard/` | Compiled Rust guard providing a process-isolated verdict path |
| `tests/` | Six suites covering injection, curation guards, scanner normalisation and the Rust guard |
| `dashboard/`, `results/`, `docs/` | Reported figures, with `scripts/verify_report_claims.py` failing the build if a quoted number stops matching a stored result |

### Two different meanings of "adversarial"

These are not the same thing and should not be consolidated:

- The **Skeptic agent** (`agents/skeptic.py`) is a *forensic* adversary. It challenges
  hypotheses about an intrusion and demands independent evidence sources. It is original
  PHANTOM functionality and runs in every analysis.
- The **red-team layer** (`phantom_ai_safety/red_team/`) is a *security* adversary. It attacks
  the agent itself to measure whether injected evidence can change its verdict. It runs as a
  separate evaluation, never as part of an investigation.

### Further reading

| Document | Covers |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The safety layer's own two-layer architecture and where the defect it repairs lives |
| [docs/RED-TEAM-ARCHITECTURE.md](docs/RED-TEAM-ARCHITECTURE.md) | The red-team implementation and its reproducible results |
| [docs/EXISTING_ARCHITECTURE.md](docs/EXISTING_ARCHITECTURE.md) | Structural map of the forensic engine, with file:line citations |
| [docs/INTEGRATION-AUDIT-COMPLETE.md](docs/INTEGRATION-AUDIT-COMPLETE.md) | The integration audit and its verification |

For command examples and setup, see the [README](README.md).

