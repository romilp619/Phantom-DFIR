# PHANTOM DFIR — Architecture

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PHANTOM DFIR v2.1                                   │
│              Parallel Hypothesis Analysis with Multi-agent                  │
│              Threat Hunting Overlay Network                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    LangGraph StateGraph                              │   │
│  │                                                                      │   │
│  │   ┌───────────┐    ┌──────────────┐    ┌──────────┐                 │   │
│  │   │ COLLECTOR │───>│ INVESTIGATOR │───>│ EVIDENCE │                 │   │
│  │   │           │    │              │    │          │                 │   │
│  │   │ • OS race │    │ • Static     │    │ • PID    │                 │   │
│  │   │ • 35+     │    │   rules      │    │   malfind│                 │   │
│  │   │   plugins │    │ • LLM hyps   │    │ • IP     │                 │   │
│  │   │ • 16      │    │ • Benign     │    │   filter │                 │   │
│  │   │   workers │    │   detection  │    │ • DLL    │                 │   │
│  │   └───────────┘    └──────────────┘    │   list   │                 │   │
│  │                                        └────┬─────┘                 │   │
│  │                                             │                       │   │
│  │                                             ▼                       │   │
│  │   ┌──────────┐                        ┌──────────┐                  │   │
│  │   │ REPORTER │<───────────────────────│ SKEPTIC  │                  │   │
│  │   │          │     (or loop back)     │          │                  │   │
│  │   │ • JSON   │◄──── reporter ────────►│ • LLM    │                  │   │
│  │   │ • MD     │                        │   debate │                  │   │
│  │   │ • Exec   │◄──── evidence ────────►│ • Rule   │                  │   │
│  │   │   log    │     (max 3 rounds)     │   verify │                  │   │
│  │   │ • Reason │                        │ • CLEARED│                  │   │
│  │   │   trace  │                        │ • Progress                  │   │
│  │   └──────────┘                        │   file   │                  │   │
│  │                                        └──────────┘                  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                          TOOL LAYER                                         │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │
│  │ vol3_tools  │  │ vol2_tools  │  │disk_correlat │  │  MCP Server     │   │
│  │             │  │             │  │              │  │                 │   │
│  │ 40+ Win     │  │ auto-profile│  │ Memory↔Disk  │  │ 20 typed tools  │   │
│  │ 30+ Linux   │  │ kdbgscan    │  │ log2timeline │  │ stdio + HTTP    │   │
│  │ plugins     │  │ hashdump    │  │ MFT parse    │  │ SHA256 verify   │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘  └────────┬────────┘   │
│         │                │                │                    │            │
├─────────┴────────────────┴────────────────┴────────────────────┴────────────┤
│                     SECURITY BOUNDARY                                       │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                 ARCHITECTURAL GUARDRAILS                              │   │
│  │                                                                      │   │
│  │  • MCP Server: Agent CANNOT run arbitrary shell commands              │   │
│  │    → Only 20 pre-defined, typed functions are exposed                │   │
│  │    → No execute_shell_cmd, no rm, no dd, no write commands           │   │
│  │                                                                      │   │
│  │  • Evidence Integrity: SHA256 hash registered at load time           │   │
│  │    → verify_integrity() checks hash before EVERY analysis            │   │
│  │    → Any modification = analysis HALTED                              │   │
│  │                                                                      │   │
│  │  • Read-Only Tool Design: All vol3/vol2 wrappers use                 │   │
│  │    subprocess.run() with capture_output=True                         │   │
│  │    → No tool writes to disk (except final reports)                   │   │
│  │    → Memory image is NEVER modified                                  │   │
│  │                                                                      │   │
│  │  • Max Iteration Cap: MAX_SKEPTIC_ROUNDS = 3                         │   │
│  │    → Hard cap prevents infinite agent loops                          │   │
│  │    → Graceful degradation: reports whatever is verified              │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                 PROMPT-BASED GUARDRAILS                               │   │
│  │                                                                      │   │
│  │  • IOC Validation: _is_valid_ioc() rejects vague LLM outputs        │   │
│  │    → IOCs must be <40 chars, no spaces, must be filename/IP/PID     │   │
│  │    → System processes (svchost, csrss, etc.) auto-excluded           │   │
│  │                                                                      │   │
│  │  • Investigator Prompt: Strict JSON schema with examples             │   │
│  │    → "BAD ioc examples" listed to prevent common LLM mistakes       │   │
│  │                                                                      │   │
│  │  NOTE: If the LLM ignores prompt restrictions, the static            │   │
│  │  rule-based fallback still generates correct hypotheses.             │   │
│  │  LLM output is MERGED with (never replaces) static baseline.        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                          DATA FLOW                                          │
│                                                                             │
│  Memory Image ──► SHA256 ──► Vol3/Vol2 Plugins ──► Raw Evidence             │
│                                                        │                    │
│  Raw Evidence ──► Investigator (Static + LLM) ──► Hypotheses               │
│                                                        │                    │
│  Hypotheses ──► Evidence Agent (PID/IP targeted) ──► Verified Sources       │
│                                                        │                    │
│  Verified Sources ──► Skeptic (debate loop) ──► Confidence Buckets          │
│       ▲                    │                         │                      │
│       └────── (max 3) ─────┘                         ▼                      │
│                                              ┌──────────────┐              │
│                                              │    REPORTS    │              │
│                                              │              │              │
│                                              │ • JSON       │              │
│                                              │ • Markdown   │              │
│                                              │ • Exec Log   │              │
│                                              │ • Progress   │              │
│                                              │ • Benchmark  │              │
│                                              └──────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
```

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
